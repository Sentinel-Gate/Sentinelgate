package cmd

import (
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// toolCacheToolLister adapts ToolCache to PermissionHealthToolLister.
type toolCacheToolLister struct {
	cache *upstream.ToolCache
}

// GetAllToolNames returns all discovered tool names from the cache.
func (a *toolCacheToolLister) GetAllToolNames() []string {
	tools := a.cache.GetAllTools()
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	return names
}

// stateIdentityLister adapts the state store and auth store to
// PermissionHealthIdentityLister, merging identities from both sources
// so that YAML-configured identities are also visible.
type stateIdentityLister struct {
	stateStore *state.FileStateStore
	authStore  *memory.AuthStore
}

// GetAllIdentities returns all known identities from state.json and the
// in-memory auth store (which also contains YAML-seeded identities).
func (a *stateIdentityLister) GetAllIdentities() []service.IdentityInfo {
	seen := make(map[string]bool)
	var infos []service.IdentityInfo

	// 1. State.json identities.
	appState, err := a.stateStore.Load()
	if err == nil && appState != nil {
		for _, id := range appState.Identities {
			seen[id.ID] = true
			infos = append(infos, service.IdentityInfo{
				ID:    id.ID,
				Name:  id.Name,
				Roles: id.Roles,
			})
		}
	}

	// 2. Auth store identities (includes YAML-seeded ones not in state.json).
	if a.authStore != nil {
		for _, id := range a.authStore.ListAllIdentities() {
			if seen[id.ID] {
				continue
			}
			roles := make([]string, len(id.Roles))
			for i, r := range id.Roles {
				roles[i] = string(r)
			}
			infos = append(infos, service.IdentityInfo{
				ID:    id.ID,
				Name:  id.Name,
				Roles: roles,
			})
		}
	}

	return infos
}
