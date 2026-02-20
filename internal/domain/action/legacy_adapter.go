package action

import (
	"context"
	"fmt"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// LegacyAdapter wraps an existing proxy.MessageInterceptor to work
// with the new ActionInterceptor interface. During migration, each
// existing interceptor is wrapped in a LegacyAdapter. The adapter:
// 1. Extracts the original mcp.Message from CanonicalAction.OriginalMessage
// 2. Calls the legacy interceptor's Intercept(ctx, msg)
// 3. If the legacy interceptor modified the message, updates CanonicalAction accordingly
// 4. Returns the CanonicalAction
type LegacyAdapter struct {
	legacy proxy.MessageInterceptor
	name   string // For logging/debugging
}

// Compile-time check that LegacyAdapter implements ActionInterceptor.
var _ ActionInterceptor = (*LegacyAdapter)(nil)

// NewLegacyAdapter creates a new LegacyAdapter wrapping the given MessageInterceptor.
func NewLegacyAdapter(legacy proxy.MessageInterceptor, name string) *LegacyAdapter {
	return &LegacyAdapter{
		legacy: legacy,
		name:   name,
	}
}

// Intercept extracts the mcp.Message from the CanonicalAction, calls the legacy
// interceptor, and syncs any changes back to the CanonicalAction.
func (a *LegacyAdapter) Intercept(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
	if action.OriginalMessage == nil {
		return nil, fmt.Errorf("LegacyAdapter(%s): OriginalMessage is nil", a.name)
	}

	mcpMsg, ok := action.OriginalMessage.(*mcp.Message)
	if !ok {
		return nil, fmt.Errorf("LegacyAdapter(%s): expected *mcp.Message, got %T", a.name, action.OriginalMessage)
	}

	// Call legacy interceptor
	resultMsg, err := a.legacy.Intercept(ctx, mcpMsg)
	if err != nil {
		return nil, err // Preserve original error for SafeErrorMessage compatibility
	}

	// Update OriginalMessage with potentially modified message
	action.OriginalMessage = resultMsg

	// Sync identity from session if the legacy interceptor set it
	// (handles AuthInterceptor setting msg.Session)
	if resultMsg != nil && resultMsg.Session != nil && action.Identity.SessionID == "" {
		roles := make([]string, len(resultMsg.Session.Roles))
		for i, r := range resultMsg.Session.Roles {
			roles[i] = string(r)
		}
		action.Identity = ActionIdentity{
			ID:        resultMsg.Session.IdentityID,
			Name:      resultMsg.Session.IdentityName,
			SessionID: resultMsg.Session.ID,
			Roles:     roles,
		}
	}

	return action, nil
}

// Name returns the adapter's name for logging/debugging.
func (a *LegacyAdapter) Name() string {
	return a.name
}
