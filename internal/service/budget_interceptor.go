package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

// BudgetBlockInterceptor denies tool calls when an identity's monthly budget
// is exceeded and the budget action is set to "block".
type BudgetBlockInterceptor struct {
	finops *FinOpsService
	next   action.ActionInterceptor
	logger *slog.Logger
}

// Compile-time check.
var _ action.ActionInterceptor = (*BudgetBlockInterceptor)(nil)

// NewBudgetBlockInterceptor creates a budget-enforcement interceptor.
// It checks the identity's cumulative monthly spend against the configured budget.
// If action is "block" and budget is exceeded, the call is denied.
func NewBudgetBlockInterceptor(finops *FinOpsService, next action.ActionInterceptor, logger *slog.Logger) *BudgetBlockInterceptor {
	return &BudgetBlockInterceptor{
		finops: finops,
		next:   next,
		logger: logger,
	}
}

func (b *BudgetBlockInterceptor) Intercept(ctx context.Context, act *action.CanonicalAction) (*action.CanonicalAction, error) {
	// Only check tool calls with a known identity.
	if act.Type != action.ActionToolCall || act.Identity.ID == "" {
		return b.next.Intercept(ctx, act)
	}

	cfg := b.finops.Config()
	if !cfg.Enabled {
		return b.next.Intercept(ctx, act)
	}

	// Check if this identity has a budget with "block" action.
	budget, hasBudget := cfg.Budgets[act.Identity.ID]
	if !hasBudget {
		return b.next.Intercept(ctx, act)
	}
	budgetAction := cfg.BudgetActions[act.Identity.ID]
	if budgetAction != "block" {
		return b.next.Intercept(ctx, act)
	}

	// Compute current month's spend for this identity.
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	report, err := b.finops.GetCostReport(ctx, start, now)
	if err != nil {
		// Fail-open: if we can't check, allow the call.
		b.logger.Warn("budget check failed, allowing call", "identity", act.Identity.ID, "error", err)
		return b.next.Intercept(ctx, act)
	}

	// Find the identity's spend from the budget status.
	for _, bs := range report.BudgetStatus {
		if bs.IdentityID == act.Identity.ID {
			b.logger.Debug("budget block: checking identity spend",
				"identity", act.Identity.ID,
				"spent", fmt.Sprintf("$%.4f", bs.Spent),
				"budget", fmt.Sprintf("$%.4f", budget),
				"exceeds", bs.Spent >= roundCost(budget),
				"tool", act.Name,
			)
			if bs.Spent >= roundCost(budget) {
				b.logger.Info("budget block: denying tool call",
					"identity", act.Identity.ID,
					"spent", fmt.Sprintf("$%.2f", bs.Spent),
					"budget", fmt.Sprintf("$%.2f", budget),
					"tool", act.Name,
				)
				return nil, fmt.Errorf("monthly budget exceeded ($%.2f / $%.2f)", bs.Spent, budget)
			}
		}
	}

	return b.next.Intercept(ctx, act)
}
