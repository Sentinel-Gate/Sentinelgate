package service

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

// FinOpsConfig holds cost estimation and budget configuration.
type FinOpsConfig struct {
	Enabled            bool               `json:"enabled"`
	DefaultCostPerCall float64            `json:"default_cost_per_call"` // default $0.01
	ToolCosts          map[string]float64 `json:"tool_costs"`            // per-tool cost override
	Budgets            map[string]float64 `json:"budgets"`               // per-identity monthly budget
	BudgetActions      map[string]string  `json:"budget_actions"`        // per-identity action: "notify" or "block"
	AlertThresholds    []float64          `json:"alert_thresholds"`      // e.g. [0.7, 0.85, 1.0]
}

func DefaultFinOpsConfig() FinOpsConfig {
	return FinOpsConfig{
		Enabled:            false,
		DefaultCostPerCall: 0.01,
		ToolCosts:          make(map[string]float64),
		Budgets:            make(map[string]float64),
		BudgetActions:      make(map[string]string),
		AlertThresholds:    []float64{0.70, 0.85, 1.0},
	}
}

// ToolCostDetail holds cost breakdown for one tool.
type ToolCostDetail struct {
	ToolName  string  `json:"tool_name"`
	TotalCost float64 `json:"total_cost"`
	CallCount int     `json:"call_count"`
	AvgCost   float64 `json:"avg_cost"`
}

// IdentityCostDetail holds cost breakdown for one identity.
type IdentityCostDetail struct {
	IdentityID   string           `json:"identity_id"`
	IdentityName string           `json:"identity_name"`
	TotalCost    float64          `json:"total_cost"`
	CallCount    int              `json:"call_count"`
	AvgCost      float64          `json:"avg_cost"`
	Tools        []ToolCostDetail `json:"tools"`
}

// BudgetStatus holds budget tracking for one identity.
type BudgetStatus struct {
	IdentityID   string  `json:"identity_id"`
	IdentityName string  `json:"identity_name,omitempty"`
	Budget       float64 `json:"budget"`
	Spent        float64 `json:"spent"`
	Percentage   float64 `json:"percentage"`
	Projection   float64 `json:"projection"`
}

// CostReport is the full cost report for a time period.
type CostReport struct {
	PeriodStart  time.Time            `json:"period_start"`
	PeriodEnd    time.Time            `json:"period_end"`
	TotalCost    float64              `json:"total_cost"`
	TotalCalls   int                  `json:"total_calls"`
	ByIdentity   []IdentityCostDetail `json:"by_identity"`
	ByTool       []ToolCostDetail     `json:"by_tool"`
	BudgetStatus []BudgetStatus       `json:"budget_status"`
	Projection   float64              `json:"projection"`
}

// FinOpsAuditReader reads audit records for cost computation.
type FinOpsAuditReader interface {
	Query(ctx context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error)
}

// FinOpsService provides cost estimation and budget tracking.
type FinOpsService struct {
	auditReader FinOpsAuditReader
	eventBus    event.Bus
	logger      *slog.Logger

	mu     sync.RWMutex
	config FinOpsConfig

	// Track which budget alerts have been sent to avoid duplicates
	alertsSent map[string]map[float64]bool // identity -> threshold -> sent
}

// maxAlertsSentEntries is the maximum number of identity entries in alertsSent
// before the map is pruned. This prevents unbounded growth from identities
// that trigger alerts but are later removed.
const maxAlertsSentEntries = 10000

// PruneAlertsSent removes all alertsSent entries if the map exceeds the
// maximum size. This is safe because alerts will simply be re-sent
// (which is acceptable since budgets reset monthly).
func (s *FinOpsService) PruneAlertsSent() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.alertsSent) > maxAlertsSentEntries {
		previousSize := len(s.alertsSent)
		s.alertsSent = make(map[string]map[float64]bool)
		s.logger.Info("pruned alertsSent map due to size limit", "previous_size", previousSize)
	}
}

func NewFinOpsService(reader FinOpsAuditReader, logger *slog.Logger) *FinOpsService {
	return &FinOpsService{
		auditReader: reader,
		logger:      logger,
		config:      DefaultFinOpsConfig(),
		alertsSent:  make(map[string]map[float64]bool),
	}
}

func (s *FinOpsService) SetEventBus(bus event.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventBus = bus
}

func (s *FinOpsService) SetConfig(cfg FinOpsConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Full reset when alert thresholds change (M-25).
	if !equalFloat64Slices(s.config.AlertThresholds, cfg.AlertThresholds) {
		s.alertsSent = make(map[string]map[float64]bool)
	} else {
		// Granular reset: clear alertsSent for identities whose budget
		// was changed or removed so notifications regenerate (N7-4A).
		for id, oldBudget := range s.config.Budgets {
			newBudget, exists := cfg.Budgets[id]
			if !exists || math.Abs(newBudget-oldBudget) > floatEpsilon {
				delete(s.alertsSent, id)
			}
		}
		// Also clear for newly added identities.
		for id := range cfg.Budgets {
			if _, existed := s.config.Budgets[id]; !existed {
				delete(s.alertsSent, id)
			}
		}
	}

	s.config = cfg
}

func (s *FinOpsService) Config() FinOpsConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// EstimateCost computes the estimated cost for a tool call.
func (s *FinOpsService) EstimateCost(toolName string, argsSize int) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if cost, ok := s.config.ToolCosts[toolName]; ok {
		return cost
	}

	// Base cost + argument size factor
	// Larger arguments → more tokens → higher cost
	baseCost := s.config.DefaultCostPerCall
	if argsSize > 1000 {
		baseCost *= 1.0 + float64(argsSize-1000)/10000.0
	}
	return baseCost
}

// GetCostReport computes costs from audit records for the given period.
func (s *FinOpsService) GetCostReport(ctx context.Context, start, end time.Time) (*CostReport, error) {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if !cfg.Enabled {
		return &CostReport{
			PeriodStart:  start,
			PeriodEnd:    end,
			ByIdentity:   []IdentityCostDetail{},
			ByTool:       []ToolCostDetail{},
			BudgetStatus: []BudgetStatus{},
		}, nil
	}

	records, _, err := s.auditReader.Query(ctx, audit.AuditFilter{
		StartTime: start,
		EndTime:   end,
		Limit:     100000,
	})
	if err != nil {
		return nil, fmt.Errorf("query audit records: %w", err)
	}

	// Aggregate costs
	identityMap := make(map[string]*identityCostAcc)
	toolMap := make(map[string]*toolCostAcc)
	totalCost := 0.0
	totalCalls := 0

	for _, r := range records {
		// Count allowed AND warned calls — both represent completed tool calls (N7-4B).
		// Only skip denied/blocked calls that never executed.
		if r.Decision != audit.DecisionAllow && r.Decision != audit.DecisionWarn {
			continue
		}
		totalCalls++

		cost := s.estimateCostForRecord(cfg, r)
		totalCost += cost

		// By identity
		acc, ok := identityMap[r.IdentityID]
		if !ok {
			idName := r.IdentityName
			if idName == "" {
				idName = r.IdentityID
			}
			acc = &identityCostAcc{name: idName, tools: make(map[string]*toolCostAcc)}
			identityMap[r.IdentityID] = acc
		}
		acc.totalCost += cost
		acc.callCount++
		toolAcc, ok := acc.tools[r.ToolName]
		if !ok {
			toolAcc = &toolCostAcc{}
			acc.tools[r.ToolName] = toolAcc
		}
		toolAcc.totalCost += cost
		toolAcc.callCount++

		// By tool (global)
		gToolAcc, ok := toolMap[r.ToolName]
		if !ok {
			gToolAcc = &toolCostAcc{}
			toolMap[r.ToolName] = gToolAcc
		}
		gToolAcc.totalCost += cost
		gToolAcc.callCount++
	}

	// Build identity details
	byIdentity := make([]IdentityCostDetail, 0, len(identityMap))
	for id, acc := range identityMap {
		tools := make([]ToolCostDetail, 0, len(acc.tools))
		for name, t := range acc.tools {
			avg := 0.0
			if t.callCount > 0 {
				avg = t.totalCost / float64(t.callCount)
			}
			tools = append(tools, ToolCostDetail{
				ToolName:  name,
				TotalCost: roundCost(t.totalCost),
				CallCount: t.callCount,
				AvgCost:   roundCost(avg),
			})
		}
		sort.Slice(tools, func(i, j int) bool {
			return tools[i].TotalCost > tools[j].TotalCost
		})

		avg := 0.0
		if acc.callCount > 0 {
			avg = acc.totalCost / float64(acc.callCount)
		}
		byIdentity = append(byIdentity, IdentityCostDetail{
			IdentityID:   id,
			IdentityName: acc.name,
			TotalCost:    roundCost(acc.totalCost),
			CallCount:    acc.callCount,
			AvgCost:      roundCost(avg),
			Tools:        tools,
		})
	}
	sort.Slice(byIdentity, func(i, j int) bool {
		return byIdentity[i].TotalCost > byIdentity[j].TotalCost
	})

	// Build tool details
	byTool := make([]ToolCostDetail, 0, len(toolMap))
	for name, t := range toolMap {
		avg := 0.0
		if t.callCount > 0 {
			avg = t.totalCost / float64(t.callCount)
		}
		byTool = append(byTool, ToolCostDetail{
			ToolName:  name,
			TotalCost: roundCost(t.totalCost),
			CallCount: t.callCount,
			AvgCost:   roundCost(avg),
		})
	}
	sort.Slice(byTool, func(i, j int) bool {
		return byTool[i].TotalCost > byTool[j].TotalCost
	})

	// Budget status
	budgetStatus := s.computeBudgetStatus(cfg, identityMap, start, end)

	// Linear projection to end of month
	projection := s.computeProjection(totalCost, start, end)

	return &CostReport{
		PeriodStart:  start,
		PeriodEnd:    end,
		TotalCost:    roundCost(totalCost),
		TotalCalls:   totalCalls,
		ByIdentity:   byIdentity,
		ByTool:       byTool,
		BudgetStatus: budgetStatus,
		Projection:   roundCost(projection),
	}, nil
}

// GetIdentityCost returns detailed cost for a specific identity.
func (s *FinOpsService) GetIdentityCost(ctx context.Context, identityID string, start, end time.Time) (*IdentityCostDetail, error) {
	report, err := s.GetCostReport(ctx, start, end)
	if err != nil {
		return nil, err
	}

	for _, id := range report.ByIdentity {
		if id.IdentityID == identityID {
			return &id, nil
		}
	}

	return &IdentityCostDetail{
		IdentityID: identityID,
		Tools:      []ToolCostDetail{},
	}, nil
}

// StartPeriodicBudgetCheck runs a background goroutine that checks budgets
// every interval and emits alerts when thresholds are crossed.
// The goroutine stops when ctx is cancelled.
func (s *FinOpsService) StartPeriodicBudgetCheck(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.RLock()
				enabled := s.config.Enabled
				s.mu.RUnlock()
				if !enabled {
					continue
				}
				now := time.Now()
				start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
				s.CheckBudgets(ctx, start, now)
			}
		}
	}()
}

// CheckBudgets checks all identities against their budgets and emits alerts.
// It also prunes the alertsSent map if it exceeds the size limit (M-25).
func (s *FinOpsService) CheckBudgets(ctx context.Context, start, end time.Time) []BudgetStatus {
	report, err := s.GetCostReport(ctx, start, end)
	if err != nil {
		s.logger.Error("failed to check budgets", "error", err)
		return nil
	}

	for _, bs := range report.BudgetStatus {
		s.checkAndEmitBudgetAlert(ctx, bs)
	}

	// Prune alertsSent map to prevent unbounded growth (M-25).
	s.PruneAlertsSent()

	return report.BudgetStatus
}

func (s *FinOpsService) estimateCostForRecord(cfg FinOpsConfig, r audit.AuditRecord) float64 {
	if cost, ok := cfg.ToolCosts[r.ToolName]; ok {
		return cost
	}

	baseCost := cfg.DefaultCostPerCall
	// Estimate argument size from latency as a rough proxy
	// Larger args → typically higher latency
	if r.LatencyMicros > 100000 { // > 100ms
		baseCost *= 1.5
	}
	return baseCost
}

func (s *FinOpsService) computeBudgetStatus(cfg FinOpsConfig, identityMap map[string]*identityCostAcc, start, end time.Time) []BudgetStatus {
	statuses := make([]BudgetStatus, 0, len(cfg.Budgets))

	for id, budget := range cfg.Budgets {
		spent := 0.0
		idName := id
		if acc, ok := identityMap[id]; ok {
			spent = acc.totalCost
			if acc.name != "" {
				idName = acc.name
			}
		}

		pct := 0.0
		if budget > 0 {
			pct = (spent / budget) * 100
		}

		projection := s.computeProjection(spent, start, end)

		statuses = append(statuses, BudgetStatus{
			IdentityID:   id,
			IdentityName: idName,
			Budget:       budget,
			Spent:        roundCost(spent),
			Percentage:   roundCost(pct),
			Projection:   roundCost(projection),
		})
	}

	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Percentage > statuses[j].Percentage
	})

	return statuses
}

func (s *FinOpsService) computeProjection(spent float64, start, end time.Time) float64 {
	now := time.Now()
	totalPeriod := end.Sub(start)
	if totalPeriod <= 0 {
		return spent
	}
	if now.After(end) {
		return spent
	}
	elapsed := now.Sub(start)
	if elapsed <= 0 {
		return spent
	}
	if float64(elapsed)/float64(totalPeriod) < 0.05 {
		return spent
	}
	ratio := float64(totalPeriod) / float64(elapsed)
	return spent * ratio
}

func (s *FinOpsService) checkAndEmitBudgetAlert(ctx context.Context, bs BudgetStatus) {
	if bs.Budget <= 0 {
		return
	}

	// Hold the lock across the entire check-and-update operation to avoid
	// TOCTOU race where SetConfig could reset alertsSent between init and read.
	s.mu.Lock()
	bus := s.eventBus
	if bus == nil {
		s.mu.Unlock()
		return
	}
	if s.alertsSent[bs.IdentityID] == nil {
		s.alertsSent[bs.IdentityID] = make(map[float64]bool)
	}
	cfg := s.config

	// Collect thresholds that need alerting while holding the lock.
	type pendingAlert struct {
		threshold float64
		eventType string
		severity  event.Severity
	}
	var alerts []pendingAlert

	ratio := bs.Spent / bs.Budget
	for _, threshold := range cfg.AlertThresholds {
		if ratio >= threshold && !s.alertsSent[bs.IdentityID][threshold] {
			s.alertsSent[bs.IdentityID][threshold] = true
			eventType := "finops.budget_warning"
			severity := event.SeverityWarning
			if threshold >= 1.0 {
				eventType = "finops.budget_exceeded"
				severity = event.SeverityCritical
			}
			alerts = append(alerts, pendingAlert{threshold, eventType, severity})
		}
	}
	s.mu.Unlock()

	// Publish events outside the lock to avoid holding it during I/O.
	for _, a := range alerts {
		bus.Publish(ctx, event.Event{
			Type:           a.eventType,
			Source:         "finops",
			Severity:       a.severity,
			RequiresAction: a.threshold >= 0.85,
			Payload: map[string]interface{}{
				"identity_id":   bs.IdentityID,
				"identity_name": bs.IdentityName,
				"budget":        bs.Budget,
				"spent":         bs.Spent,
				"percentage":    bs.Percentage,
				"threshold":     a.threshold * 100,
			},
		})
	}
}

type identityCostAcc struct {
	name      string
	totalCost float64
	callCount int
	tools     map[string]*toolCostAcc
}

type toolCostAcc struct {
	totalCost float64
	callCount int
}

func roundCost(v float64) float64 {
	return math.Round(v*10000) / 10000
}

// floatEpsilon is the tolerance for floating-point comparison (L-40).
const floatEpsilon = 1e-9

// equalFloat64Slices reports whether two float64 slices have the same elements
// using epsilon-based comparison instead of strict equality (L-40).
func equalFloat64Slices(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if math.Abs(a[i]-b[i]) > floatEpsilon {
			return false
		}
	}
	return true
}

// isFiniteNonNegative returns true if v is a finite, non-negative float64.
// Used to reject NaN, Inf, and negative values for cost/budget fields (M-34, L-45).
func isFiniteNonNegative(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

// ValidateFinOpsConfig validates all float64 fields in a FinOpsConfig,
// returning an error if any value is NaN, Inf, or negative (M-34),
// or if AlertThresholds are out of range / not ascending (M-36).
// This is used both by the API handler and at boot when loading from state.json (L-45).
func ValidateFinOpsConfig(cfg FinOpsConfig) error {
	// Validate DefaultCostPerCall (M-34)
	if !isFiniteNonNegative(cfg.DefaultCostPerCall) {
		return fmt.Errorf("default_cost_per_call must be a finite non-negative number")
	}

	// Validate per-tool costs (M-34)
	for name, cost := range cfg.ToolCosts {
		if !isFiniteNonNegative(cost) {
			return fmt.Errorf("tool_costs[%q] must be a finite non-negative number", name)
		}
	}

	// Validate per-identity budgets (M-34)
	for id, budget := range cfg.Budgets {
		if !isFiniteNonNegative(budget) {
			return fmt.Errorf("budgets[%q] must be a finite non-negative number", id)
		}
	}

	// Validate per-identity budget actions
	for id, act := range cfg.BudgetActions {
		if act != "notify" && act != "block" {
			return fmt.Errorf("budget_actions[%q] must be \"notify\" or \"block\"", id)
		}
	}

	// Validate AlertThresholds: finite, in [0.0, 1.0], ascending order (M-36)
	for i, t := range cfg.AlertThresholds {
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return fmt.Errorf("alert_thresholds[%d] must be a finite number", i)
		}
		if t < 0.0 || t > 1.0 {
			return fmt.Errorf("alert_thresholds[%d] must be between 0.0 and 1.0", i)
		}
		if i > 0 && t <= cfg.AlertThresholds[i-1] {
			return fmt.Errorf("alert_thresholds must be in strictly ascending order")
		}
	}

	return nil
}
