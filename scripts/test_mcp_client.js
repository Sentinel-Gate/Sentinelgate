#!/usr/bin/env node
/**
 * Minimal MCP client testing through SentinelGate proxy — Session A6.
 */
const PROXY_URL = process.env.SG_PROXY_URL || "http://localhost:8080/mcp";
const API_KEY = process.env.SG_API_KEY || "";

let passed = 0;
let failed = 0;
let reqId = 0;

async function mcpCall(method, params = {}) {
  reqId++;
  try {
    const resp = await fetch(PROXY_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: reqId, method, params }),
      signal: AbortSignal.timeout(30000)
    });
    return await resp.json();
  } catch (e) {
    return { error: String(e) };
  }
}

function check(testName, condition, detail = "") {
  if (condition) {
    passed++;
    console.log(`PASS:${testName}:${detail}`);
  } else {
    failed++;
    console.log(`FAIL:${testName}:${detail}`);
  }
}

async function main() {
  if (!API_KEY) {
    console.log("FAIL:setup:SG_API_KEY environment variable required");
    process.exit(1);
  }

  // Test 1: Initialize
  let result = await mcpCall("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "nodejs-test-agent", version: "1.0" }
  });
  const hasServerInfo = result?.result?.serverInfo != null;
  check("initialize", hasServerInfo,
    result?.result?.serverInfo?.name || "?");

  // Test 2: List tools
  result = await mcpCall("tools/list");
  const tools = result?.result?.tools || [];
  check("tools_list", tools.length > 0, `${tools.length} tools`);
  tools.slice(0, 5).forEach(t =>
    console.log(`  TOOL: ${t.name}: ${(t.description || "").slice(0, 60)}`)
  );

  // Test 3: Call echo tool
  result = await mcpCall("tools/call", {
    name: "echo",
    arguments: { message: "Hello from Node.js agent!" }
  });
  let contentText = result?.result?.content?.[0]?.text || "";
  check("tool_call_echo", result?.result != null && contentText.includes("Hello"),
    contentText.slice(0, 80));

  // Test 4: Call get-sum tool
  result = await mcpCall("tools/call", {
    name: "get-sum",
    arguments: { a: 7, b: 13 }
  });
  contentText = result?.result?.content?.[0]?.text || "";
  check("tool_call_get_sum", result?.result != null && contentText.includes("20"),
    contentText.slice(0, 80));

  // Summary
  console.log(`SUMMARY:${passed}:${failed}`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(e => {
  console.log(`FAIL:uncaught:${e.message}`);
  process.exit(1);
});
