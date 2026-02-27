package action

import "context"

// ActionInterceptor processes CanonicalActions through the security chain.
// This is the protocol-agnostic replacement for proxy.MessageInterceptor.
// During migration, LegacyAdapter wraps existing MessageInterceptors.
type ActionInterceptor interface {
	// Intercept processes a CanonicalAction and returns the result.
	// Returns the (possibly modified) action and an error if rejected.
	Intercept(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error)
}

// ActionInterceptorFunc is an adapter to allow the use of ordinary functions
// as ActionInterceptors. Like http.HandlerFunc, it enables inline interceptors.
type ActionInterceptorFunc func(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error)

// Intercept calls f(ctx, action).
func (f ActionInterceptorFunc) Intercept(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
	return f(ctx, action)
}

// Compile-time check that ActionInterceptorFunc implements ActionInterceptor.
var _ ActionInterceptor = ActionInterceptorFunc(nil)
