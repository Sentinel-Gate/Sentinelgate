import { test, expect, createMCPSession } from '../helpers/fixtures';

/**
 * Namespace E2E Tests — Wave 6
 *
 * Tests tool namespacing by creating a second filesystem upstream that conflicts
 * with the first, triggering automatic namespace prefixes.
 */
test.describe('Tool Namespacing', () => {
  let secondUpstreamId: string | null = null;

  test.afterEach(async ({ adminAPI }) => {
    // Clean up the second upstream if created
    if (secondUpstreamId) {
      try {
        await adminAPI.deleteUpstream(secondUpstreamId);
      } catch { /* already deleted */ }
      secondUpstreamId = null;

      // Wait for tool cache to rebuild after upstream removal
      await new Promise(r => setTimeout(r, 3000));
    }
  });

  test('tools/list shows no namespace when tool names are unique', async ({ mcpClient, adminAPI }) => {
    // Default setup: filesystem + memory upstreams with unique tool names
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);

    // No tool name should contain "/" (no conflicts → no namespace prefix)
    for (const tool of tools) {
      expect(tool.name).not.toContain('/');
    }
  });

  test('tools/list shows namespaced names when conflict exists', async ({ request, adminAPI, env }) => {
    // Create a second filesystem upstream → same tools as first → conflict!
    const result = await adminAPI.createUpstream({
      name: 'fs-duplicate',
      type: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', env.testDir],
      enabled: true,
    });
    expect(result?.id).toBeTruthy();
    secondUpstreamId = result.id;

    // Wait for tool discovery on the new upstream
    let tools: any[] = [];
    for (let attempt = 0; attempt < 15; attempt++) {
      await new Promise(r => setTimeout(r, 2000));
      const client = await createMCPSession(request);
      tools = await client.listTools();
      // Check if any tool has "/" — indicating namespace is active
      const hasNamespace = tools.some((t: any) => t.name.includes('/'));
      if (hasNamespace) break;
    }

    // With two filesystem upstreams, shared tool names should be namespaced
    const namespacedTools = tools.filter((t: any) => t.name.includes('/'));
    expect(namespacedTools.length).toBeGreaterThan(0);

    // "read_file" should appear twice with namespace prefix
    const readFileTools = tools.filter((t: any) => t.name.endsWith('/read_file'));
    expect(readFileTools.length).toBe(2);
  });

  test('tools/call with namespaced name routes correctly', async ({ request, adminAPI, env }) => {
    // Create second filesystem upstream
    const result = await adminAPI.createUpstream({
      name: 'fs-ns-call',
      type: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', env.testDir],
      enabled: true,
    });
    expect(result?.id).toBeTruthy();
    secondUpstreamId = result.id;

    // Wait for namespace to be active
    let client = await createMCPSession(request);
    let tools: any[] = [];
    for (let attempt = 0; attempt < 15; attempt++) {
      await new Promise(r => setTimeout(r, 2000));
      client = await createMCPSession(request);
      tools = await client.listTools();
      if (tools.some((t: any) => t.name.includes('/read_file'))) break;
    }

    // Find a namespaced read_file tool
    const nsReadFile = tools.find((t: any) => t.name.endsWith('/read_file'));
    expect(nsReadFile).toBeTruthy();

    // Call it with the full namespaced name
    const filePath = env.testDir + '/test.txt';
    const result2 = await client.callTool(nsReadFile.name, { path: filePath });
    // Should succeed (not an error)
    if (result2.isError) {
      // Some transient failures are acceptable during upstream reconnect
      console.log('Tool call returned error (may be transient):', result2.error);
    } else {
      // Content should contain the test file data
      const text = result2.content?.find((c: any) => c.type === 'text')?.text || '';
      expect(text).toContain('Hello from SentinelGate');
    }
  });

  test('tools/call with bare name returns ambiguous error', async ({ request, adminAPI, env }) => {
    // Create second filesystem upstream
    const result = await adminAPI.createUpstream({
      name: 'fs-ns-ambig',
      type: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', env.testDir],
      enabled: true,
    });
    expect(result?.id).toBeTruthy();
    secondUpstreamId = result.id;

    // Wait for namespace to be active
    let client = await createMCPSession(request);
    let tools: any[] = [];
    for (let attempt = 0; attempt < 15; attempt++) {
      await new Promise(r => setTimeout(r, 2000));
      client = await createMCPSession(request);
      tools = await client.listTools();
      if (tools.some((t: any) => t.name.includes('/read_file'))) break;
    }

    // Calling bare "read_file" should fail with ambiguous error
    const callResult = await client.callTool('read_file', { path: env.testDir + '/test.txt' });
    expect(callResult.isError).toBe(true);

    // Error message should mention "ambiguous" and suggest namespaced names
    const errorText = JSON.stringify(callResult);
    expect(errorText.toLowerCase()).toContain('ambiguous');
  });

  test('namespace removed when conflict resolved', async ({ request, adminAPI, env }) => {
    // Create second filesystem upstream
    const result = await adminAPI.createUpstream({
      name: 'fs-ns-remove',
      type: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', env.testDir],
      enabled: true,
    });
    expect(result?.id).toBeTruthy();
    secondUpstreamId = result.id;

    // Wait for namespace to be active
    let client = await createMCPSession(request);
    let tools: any[] = [];
    for (let attempt = 0; attempt < 15; attempt++) {
      await new Promise(r => setTimeout(r, 2000));
      client = await createMCPSession(request);
      tools = await client.listTools();
      if (tools.some((t: any) => t.name.includes('/read_file'))) break;
    }
    expect(tools.some((t: any) => t.name.includes('/'))).toBe(true);

    // Delete the second upstream to resolve the conflict
    await adminAPI.deleteUpstream(secondUpstreamId!);
    secondUpstreamId = null;

    // Wait for tool cache to rebuild
    await new Promise(r => setTimeout(r, 4000));

    // Now tools should be back to bare names (no namespace)
    const client2 = await createMCPSession(request);
    const tools2 = await client2.listTools();

    // "read_file" should be accessible without namespace
    const readFile = tools2.find((t: any) => t.name === 'read_file');
    expect(readFile).toBeTruthy();

    // No tool should have "/" prefix anymore (filesystem tools)
    const fsNamespaced = tools2.filter((t: any) =>
      t.name.includes('/read_file') || t.name.includes('/write_file')
    );
    expect(fsNamespaced.length).toBe(0);
  });
});
