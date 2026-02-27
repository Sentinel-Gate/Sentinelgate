import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '../helpers/fixtures';

test.describe('Tools Call', () => {
  const createdFiles: string[] = [];

  test.afterEach(async () => {
    for (const f of createdFiles) {
      try { fs.unlinkSync(f); } catch { /* ignore */ }
    }
    createdFiles.length = 0;
  });

  test('read_file returns file content', async ({ mcpClient, env }) => {
    const text = await mcpClient.callToolText('read_file', {
      path: path.join(env.testDir, 'test.txt'),
    });
    expect(text).toContain('Hello from SentinelGate');
  });

  test('list_directory returns entries', async ({ mcpClient, env }) => {
    const text = await mcpClient.callToolText('list_directory', {
      path: env.testDir,
    });
    expect(text).toContain('test.txt');
    expect(text).toContain('subdir');
  });

  test('read nested file', async ({ mcpClient, env }) => {
    const text = await mcpClient.callToolText('read_file', {
      path: path.join(env.testDir, 'subdir', 'nested.txt'),
    });
    expect(text).toContain('Nested file content');
  });

  test('write_file creates file', async ({ mcpClient, env }) => {
    const filePath = path.join(env.testDir, 'e2e-created.txt');
    const content = 'created by e2e test';

    const writeResult = await mcpClient.callTool('write_file', {
      path: filePath,
      content,
    });
    expect(writeResult.isError).toBeFalsy();
    createdFiles.push(filePath);

    const readBack = await mcpClient.callToolText('read_file', { path: filePath });
    expect(readBack).toContain(content);
  });

  test('memory create and read', async ({ mcpClient }) => {
    const createResult = await mcpClient.callTool('create_entities', {
      entities: [{
        name: 'e2e-test-entity',
        entityType: 'test',
        observations: ['E2E test entity created by Playwright'],
      }],
    });
    expect(createResult.isError).toBeFalsy();

    const graphText = await mcpClient.callToolText('read_graph');
    expect(graphText).toContain('e2e-test-entity');

    try {
      await mcpClient.callTool('delete_entities', { entityNames: ['e2e-test-entity'] });
    } catch { /* best-effort cleanup */ }
  });

  test('non-existent tool returns error', async ({ mcpClient }) => {
    const result = await mcpClient.callTool('this_tool_does_not_exist', {});
    expect(result.isError).toBe(true);
    if (result.error) {
      expect(result.error.code).toBe(-32601);
    }
  });

  test('tool call result has content array', async ({ mcpClient, env }) => {
    const result = await mcpClient.callTool('read_file', {
      path: path.join(env.testDir, 'test.txt'),
    });
    expect(result.isError).toBeFalsy();
    expect(Array.isArray(result.content)).toBe(true);
    expect(result.content!.length).toBeGreaterThanOrEqual(1);
    for (const item of result.content!) {
      expect(typeof item.type).toBe('string');
      expect(typeof item.text).toBe('string');
    }
  });

  test('search_files finds matching files', async ({ mcpClient, env }) => {
    const text = await mcpClient.callToolText('search_files', {
      path: env.testDir,
      pattern: '**/*.txt',
    });
    expect(text.length).toBeGreaterThan(0);
    expect(text).toContain('test.txt');
  });
});
