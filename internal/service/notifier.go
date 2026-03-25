package service

// ToolChangeNotifier is called when the tool list changes due to upstream
// additions, removals, or re-discovery. Implementations broadcast
// notifications/tools/list_changed to connected MCP clients.
type ToolChangeNotifier interface {
	NotifyToolsChanged()
}
