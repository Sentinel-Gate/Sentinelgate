import { test, expect, MCPClient } from '../helpers/fixtures';

test.describe('Tools List', () => {
  test('returns tools array', async ({ mcpClient }) => {
    const tools = await mcpClient.listTools();
    expect(Array.isArray(tools)).toBe(true);
    expect(tools.length).toBeGreaterThan(0);
  });

  test('includes filesystem tools', async ({ mcpClient }) => {
    const tools = await mcpClient.listTools();
    const toolNames = tools.map((t: any) => t.name);

    // Filesystem server exposes tools like read_file, write_file, list_directory, etc.
    const fsToolNames = ['read_file', 'write_file', 'list_directory', 'search_files'];
    const foundFsTools = fsToolNames.filter(name => toolNames.includes(name));

    // At least some filesystem tools should be present
    expect(foundFsTools.length).toBeGreaterThan(0);
  });

  test('includes memory tools', async ({ mcpClient }) => {
    const tools = await mcpClient.listTools();
    const toolNames = tools.map((t: any) => t.name);

    // Memory server exposes tools like create_entities, read_graph, search_nodes, etc.
    const memToolNames = ['create_entities', 'read_graph', 'search_nodes', 'open_nodes', 'add_relations'];
    const foundMemTools = memToolNames.filter(name => toolNames.includes(name));

    // At least some memory tools should be present
    expect(foundMemTools.length).toBeGreaterThan(0);
  });

  test('each tool has name, description, inputSchema', async ({ mcpClient }) => {
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);

    // Verify the first tool has all required fields
    const tool = tools[0];
    expect(typeof tool.name).toBe('string');
    expect(tool.name.length).toBeGreaterThan(0);

    expect(typeof tool.description).toBe('string');
    expect(tool.description.length).toBeGreaterThan(0);

    expect(tool.inputSchema).toBeDefined();
    expect(tool.inputSchema.type).toBe('object');

    // Verify a few more tools to increase confidence
    for (const t of tools.slice(0, 5)) {
      expect(typeof t.name).toBe('string');
      expect(t.name.length).toBeGreaterThan(0);
      expect(typeof t.description).toBe('string');
      expect(t.inputSchema).toBeDefined();
      expect(t.inputSchema.type).toBe('object');
    }
  });

  test('tool count matches expected range', async ({ mcpClient }) => {
    const tools = await mcpClient.listTools();

    // filesystem (~14 tools) + memory (~9 tools) = ~23 tools
    // Allow some flexibility: between 15 and 30
    expect(tools.length).toBeGreaterThanOrEqual(15);
    expect(tools.length).toBeLessThanOrEqual(30);
  });

  test('tools/list with unknown cursor returns all tools', async ({ mcpClient }) => {
    // First get the full list to know expected count
    const allTools = await mcpClient.listTools();
    const expectedCount = allTools.length;

    // Send tools/list with a nonexistent cursor — server should ignore it
    // and return all tools (no pagination implemented)
    const res = await mcpClient.send('tools/list', { cursor: 'nonexistent' });
    expect(res.error).toBeUndefined();
    expect(res.result).toBeDefined();

    const tools = res.result.tools || [];
    expect(tools.length).toBe(expectedCount);
  });
});
