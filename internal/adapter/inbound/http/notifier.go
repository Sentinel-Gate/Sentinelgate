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
