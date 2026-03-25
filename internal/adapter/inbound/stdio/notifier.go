package stdio

// StdioToolChangeNotifier implements service.ToolChangeNotifier by writing
// notifications/tools/list_changed to stdout for stdio-connected MCP clients.
type StdioToolChangeNotifier struct {
	transport *StdioTransport
}

// NewStdioToolChangeNotifier creates a new notifier backed by the stdio transport.
func NewStdioToolChangeNotifier(t *StdioTransport) *StdioToolChangeNotifier {
	return &StdioToolChangeNotifier{transport: t}
}

// NotifyToolsChanged writes a tools/list_changed notification to stdout.
func (n *StdioToolChangeNotifier) NotifyToolsChanged() {
	n.transport.SendNotification("notifications/tools/list_changed")
}
