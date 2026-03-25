package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/lifecycle"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// bootStores initializes all in-memory stores, loads state.json, seeds
// config data, and creates the upstream service (BOOT-03 + BOOT-04).
func (bc *bootContext) bootStores(ctx context.Context) error {
	// BOOT-03: Load/create state.json
	bc.stateStore = state.NewFileStateStore(bc.statePath, bc.logger)

	// L-20: Check whether state.json exists before loading. Only save on
	// first boot (file missing) to avoid unconditionally overwriting the
	// .bak file when no migrations have been applied.
	_, statErr := os.Stat(bc.statePath)
	isFirstBoot := errors.Is(statErr, fs.ErrNotExist)

	appState, err := bc.stateStore.Load()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}
	if isFirstBoot {
		if err := bc.stateStore.Save(appState); err != nil {
			return fmt.Errorf("failed to save initial state: %w", err)
		}
	}
	bc.appState = appState
	bc.logger.Info("state loaded",
		"path", bc.statePath,
		"upstreams", len(appState.Upstreams),
		"policies", len(appState.Policies),
		"default_policy", appState.DefaultPolicy,
	)

	// BOOT-04: Populate in-memory stores
	bc.authStore = memory.NewAuthStore()
	bc.sessionStore = memory.NewSessionStore()
	// L-37: Pass context.Background() so the cleanup goroutine stays alive
	// until the explicit Stop() lifecycle hook, rather than exiting early
	// when the signal context is cancelled.
	bc.sessionStore.StartCleanup(context.Background())
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "session-store-stop", Phase: lifecycle.PhaseDrainRequests,
		Timeout: 3 * time.Second,
		Fn:      func(ctx context.Context) error { bc.sessionStore.Stop(); return nil },
	})
	bc.policyStore = memory.NewPolicyStore()
	bc.upstreamStore = memory.NewUpstreamStore()

	// Seed YAML identities/policies as READ-ONLY base
	if err := seedAuthFromConfig(bc.cfg, bc.authStore); err != nil {
		return fmt.Errorf("failed to seed auth: %w", err)
	}
	bc.logger.Debug("seeded auth from YAML config",
		"identities", len(bc.cfg.Auth.Identities),
		"api_keys", len(bc.cfg.Auth.APIKeys),
	)

	// Seed state.json identities and API keys
	seedAuthFromState(appState, bc.authStore, bc.cfg, bc.logger)

	if err := seedPoliciesFromConfig(bc.cfg, bc.policyStore); err != nil {
		return fmt.Errorf("failed to seed policies: %w", err)
	}
	bc.logger.Debug("seeded policies from YAML config", "policies", len(bc.cfg.Policies))

	// Backward compat: migrate YAML upstream to state.json if needed
	if bc.cfg.HasYAMLUpstream() && len(appState.Upstreams) == 0 {
		yamlUpstream := migrateYAMLUpstream(bc.cfg)
		appState.Upstreams = append(appState.Upstreams, yamlUpstream)
		if err := bc.stateStore.Save(appState); err != nil {
			return fmt.Errorf("failed to save migrated upstream: %w", err)
		}
		bc.logger.Info("migrated YAML upstream to state.json",
			"name", yamlUpstream.Name,
			"type", yamlUpstream.Type,
		)
	}

	// Create upstream service and load state.json upstreams
	bc.upstreamService = service.NewUpstreamService(bc.upstreamStore, bc.stateStore, bc.logger)
	if err := bc.upstreamService.LoadFromState(ctx, appState); err != nil {
		return fmt.Errorf("failed to load upstreams from state: %w", err)
	}

	return nil
}

// seedAuthFromConfig seeds identities and API keys from configuration.
func seedAuthFromConfig(cfg *config.OSSConfig, authStore *memory.AuthStore) error {
	// L-66: Detect duplicate identity IDs in YAML config.
	seenIDs := make(map[string]bool, len(cfg.Auth.Identities))
	for _, identityCfg := range cfg.Auth.Identities {
		if seenIDs[identityCfg.ID] {
			slog.Warn("duplicate identity ID in config, later definition overwrites",
				"id", identityCfg.ID)
		}
		seenIDs[identityCfg.ID] = true
		roles := make([]auth.Role, len(identityCfg.Roles))
		for i, role := range identityCfg.Roles {
			roles[i] = auth.Role(role)
		}
		authStore.AddIdentity(&auth.Identity{
			ID:    identityCfg.ID,
			Name:  identityCfg.Name,
			Roles: roles,
		})
	}

	for _, keyCfg := range cfg.Auth.APIKeys {
		hash := strings.TrimPrefix(keyCfg.KeyHash, "sha256:")
		// M-9: Warn when YAML keys use weak SHA-256 hashing (unsalted, GPU-brute-forceable).
		if !strings.HasPrefix(keyCfg.KeyHash, "$argon2id$") {
			slog.Warn("API key uses weak SHA-256 hash, consider upgrading to Argon2id",
				"identity_id", keyCfg.IdentityID)
		}
		authStore.AddKey(&auth.APIKey{
			Key:        hash,
			IdentityID: keyCfg.IdentityID,
			CreatedAt:  time.Now(),
		})
	}

	return nil
}

// seedAuthFromState loads identities and API keys from state.json.
// M-11: Before adding, it removes API keys that were previously loaded from
// state but are no longer present (revoked/deleted). YAML-seeded entries are
// preserved; only state-sourced key entries that disappeared are purged.
// Identity entries are overwritten by AddIdentity (map key = ID), so updates
// are handled. Deleted identities become unreachable once their keys are removed.
func seedAuthFromState(appState *state.AppState, authStore *memory.AuthStore, cfg *config.OSSConfig, logger *slog.Logger) {
	// M-11: Build set of YAML-sourced key hashes so we never remove
	// config-seeded entries.
	yamlKeyHashes := make(map[string]bool, len(cfg.Auth.APIKeys))
	for _, k := range cfg.Auth.APIKeys {
		yamlKeyHashes[strings.TrimPrefix(k.KeyHash, "sha256:")] = true
	}

	// M-11: Build the set of valid (non-revoked) state key hashes.
	stateKeyHashes := make(map[string]bool, len(appState.APIKeys))
	for _, key := range appState.APIKeys {
		if !key.Revoked {
			stateKeyHashes[key.KeyHash] = true
		}
	}

	// M-11: Remove stale API keys that are not in YAML config and not in
	// current state (i.e. were revoked/deleted from state.json since last seed).
	existingKeys, _ := authStore.ListAPIKeys(context.Background())
	for _, existing := range existingKeys {
		if yamlKeyHashes[existing.Key] || stateKeyHashes[existing.Key] {
			continue
		}
		authStore.RemoveKey(existing.Key)
	}

	// Add/update all current state identities. AddIdentity overwrites by ID,
	// so updated names/roles are applied and new identities are added.
	for _, identity := range appState.Identities {
		roles := make([]auth.Role, len(identity.Roles))
		for i, role := range identity.Roles {
			roles[i] = auth.Role(role)
		}
		authStore.AddIdentity(&auth.Identity{
			ID:    identity.ID,
			Name:  identity.Name,
			Roles: roles,
		})
	}

	// Add all non-revoked state API keys.
	for _, key := range appState.APIKeys {
		if key.Revoked {
			continue
		}
		authStore.AddKey(&auth.APIKey{
			Key:        key.KeyHash,
			Prefix:     key.KeyPrefix,
			IdentityID: key.IdentityID,
			Name:       key.Name,
			CreatedAt:  key.CreatedAt,
			ExpiresAt:  key.ExpiresAt,
			Revoked:    key.Revoked,
		})
	}

	logger.Debug("seeded auth from state.json",
		"identities", len(appState.Identities),
		"api_keys", len(appState.APIKeys),
	)
}

// seedPoliciesFromConfig seeds policies from configuration.
func seedPoliciesFromConfig(cfg *config.OSSConfig, policyStore *memory.MemoryPolicyStore) error {
	now := time.Now()
	// L-67: Detect duplicate policy names in YAML config.
	seenPolicies := make(map[string]bool, len(cfg.Policies))
	for _, policyCfg := range cfg.Policies {
		if seenPolicies[policyCfg.Name] {
			slog.Warn("duplicate policy name in config, later definition overwrites",
				"name", policyCfg.Name)
		}
		seenPolicies[policyCfg.Name] = true
		rules := make([]policy.Rule, len(policyCfg.Rules))
		for i, ruleCfg := range policyCfg.Rules {
			cond := ruleCfg.Condition
			if cond == "" {
				cond = "true" // default: match all calls
			}
			rules[i] = policy.Rule{
				ID:        fmt.Sprintf("%s-rule-%d", policyCfg.Name, i),
				Name:      ruleCfg.Name,
				Condition: cond,
				Action:    policy.Action(ruleCfg.Action),
				ToolMatch: "*",
				Priority:  len(policyCfg.Rules) - i,
			}
		}
		policyStore.AddPolicy(&policy.Policy{
			ID:        policyCfg.Name,
			Name:      policyCfg.Name,
			Enabled:   true,
			Rules:     rules,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return nil
}

// migrateYAMLUpstream creates a state.json entry from the YAML single upstream.
func migrateYAMLUpstream(cfg *config.OSSConfig) state.UpstreamEntry {
	now := time.Now().UTC()
	entry := state.UpstreamEntry{
		ID:        uuid.New().String(),
		Name:      "default",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if cfg.Upstream.HTTP != "" {
		entry.Type = string(upstream.UpstreamTypeHTTP)
		entry.URL = cfg.Upstream.HTTP
	} else {
		entry.Type = string(upstream.UpstreamTypeStdio)
		entry.Command = cfg.Upstream.Command
		entry.Args = cfg.Upstream.Args
	}
	return entry
}
