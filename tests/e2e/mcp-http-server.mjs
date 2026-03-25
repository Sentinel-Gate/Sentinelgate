import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import http from "http";
import crypto from "crypto";

function createServer() {
  const srv = new Server(
    { name: "test-http-mcp", version: "1.0.0" },
    { capabilities: { tools: { listChanged: false } } }
  );
  srv.setRequestHandler(ListToolsRequestSchema, async () => {
    console.log("[tools/list] called");
    return {
      tools: [
        { name: "get_weather", description: "Get weather", inputSchema: { type: "object", properties: { city: { type: "string" } }, required: ["city"] } },
        { name: "calculate", description: "Math", inputSchema: { type: "object", properties: { expression: { type: "string" } }, required: ["expression"] } },
      ]
    };
  });
  srv.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    console.log(`[tools/call] ${name}(${JSON.stringify(args)})`);
    if (name === "get_weather") return { content: [{ type: "text", text: `Weather in ${args.city}: 22°C, sunny` }] };
    if (name === "calculate") return { content: [{ type: "text", text: `Result: ${args.expression}` }] };
    return { content: [{ type: "text", text: `Unknown: ${name}` }], isError: true };
  });
  return srv;
}

const sessions = new Map();

const httpServer = http.createServer(async (req, res) => {
  console.log(`[${req.method}] session=${req.headers["mcp-session-id"] || "none"} url=${req.url}`);
  
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  const sessionId = req.headers["mcp-session-id"];
  
  if (sessionId && sessions.has(sessionId)) {
    console.log(`[EXISTING SESSION] ${sessionId}`);
    await sessions.get(sessionId).handleRequest(req, res);
    return;
  }

  if (req.method === "POST") {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
    });
    const srv = createServer();
    await srv.connect(transport);
    
    await transport.handleRequest(req, res);
    if (transport.sessionId) {
      sessions.set(transport.sessionId, transport);
      console.log(`[NEW SESSION] ${transport.sessionId}`);
    }
    return;
  }

  res.writeHead(400); res.end("Bad request");
});

httpServer.listen(9999, "127.0.0.1", () => console.log("MCP HTTP on :9999"));
