package http

// HTTPToolChangeNotifier implements service.ToolChangeNotifier by broadcasting
// notifications/tools/list_changed to all connected SSE clients.
type HTTPToolChangeNotifier struct {
	transport *HTTPTransport
}

// NewHTTPToolChangeNotifier creates a new notifier backed by the HTTP transport.
func NewHTTPToolChangeNotifier(t *HTTPTransport) *HTTPToolChangeNotifier {
	return &HTTPToolChangeNotifier{transport: t}
}

// NotifyToolsChanged broadcasts a tools/list_changed notification.
func (n *HTTPToolChangeNotifier) NotifyToolsChanged() {
	n.transport.BroadcastNotification("notifications/tools/list_changed")
}

// HTTPNotificationForwarder implements proxy.NotificationForwarder by
// broadcasting raw upstream notifications to all connected SSE clients (H-4).
type HTTPNotificationForwarder struct {
	transport *HTTPTransport
}

// NewHTTPNotificationForwarder creates a forwarder backed by the HTTP transport.
func NewHTTPNotificationForwarder(t *HTTPTransport) *HTTPNotificationForwarder {
	return &HTTPNotificationForwarder{transport: t}
}

// ForwardNotification broadcasts a raw JSON-RPC notification to all SSE clients.
func (f *HTTPNotificationForwarder) ForwardNotification(data []byte) {
	f.transport.sessions.broadcast(data)
}
