import { execSync, spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import * as crypto from 'crypto';

const ROOT = path.resolve(__dirname, '..', '..');
const BINARY = path.join(ROOT, 'sentinel-gate');
const STATE_FILE = path.join(ROOT, 'state.json');
// Resolve /tmp to real path (macOS: /tmp → /private/tmp) so the filesystem
// MCP server's allowed-directory check matches the paths we pass in tool calls.
const TEST_DIR = path.join(fs.realpathSync('/tmp'), 'sg-e2e-test');

let serverProcess: ChildProcess | null = null;

function waitForServer(url: string, timeoutMs = 30_000): Promise<void> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      const req = http.get(url, (res) => {
        res.resume();
        if (res.statusCode && res.statusCode < 500) {
          resolve();
        } else {
          retry();
        }
      });
      req.on('error', () => retry());
      req.setTimeout(2000, () => { req.destroy(); retry(); });
    };
    const retry = () => {
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`Server did not start within ${timeoutMs}ms`));
      } else {
        setTimeout(check, 500);
      }
    };
    check();
  });
}

/**
 * Generate a CSRF token client-side. The Go CSRF middleware uses double-submit
 * cookie pattern: it only checks that the Cookie value matches the X-CSRF-Token
 * header. It does NOT verify the token was server-issued (confirmed by Go unit tests).
 */
function generateCSRFToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/** Make an admin API POST/PUT/DELETE with CSRF token (double-submit pattern). */
async function adminRequest(method: string, apiPath: string, body?: any): Promise<any> {
  const csrfToken = generateCSRFToken();
  const data = body ? JSON.stringify(body) : '';

  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
      'Cookie': `sentinel_csrf_token=${csrfToken}`,
    };
    if (data) {
      headers['Content-Length'] = String(Buffer.byteLength(data));
    }

    const req = http.request({
      hostname: 'localhost',
      port: 8080,
      path: `/admin/api${apiPath}`,
      method,
      headers,
    }, (res) => {
      let responseBody = '';
      res.on('data', (chunk) => responseBody += chunk);
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 400) {
          console.error(`  [${method} ${apiPath}] HTTP ${res.statusCode}: ${responseBody.substring(0, 200)}`);
        }
        try {
          resolve(JSON.parse(responseBody));
        } catch {
          resolve(responseBody);
        }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

export default async function globalSetup() {
  console.log('\n=== SentinelGate E2E Global Setup ===\n');

  // 1. Build binary (skip go clean -cache to avoid issues with certain Go versions)
  console.log('Building sentinel-gate binary...');
  try {
    execSync('go build -o sentinel-gate ./cmd/sentinel-gate', {
      cwd: ROOT,
      stdio: 'inherit',
      timeout: 120_000,
    });
    console.log('Build complete.');
  } catch (err) {
    if (fs.existsSync(BINARY)) {
      console.log('Build failed but binary exists, continuing with existing binary.');
    } else {
      throw err;
    }
  }

  // 2. Reset state.json to clean state
  console.log('Resetting state.json...');
  const cleanState = {
    version: '1',
    default_policy: 'allow',
    upstreams: [],
    policies: [],
    identities: [],
    api_keys: [],
    outbound_rules: [],
    content_scanning_config: { mode: 'monitor', enabled: false },
    recording_config: { enabled: false, record_payloads: false, storage_dir: path.join(fs.realpathSync('/tmp'), 'sg-recordings') },
    admin_password_hash: '',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  fs.writeFileSync(STATE_FILE, JSON.stringify(cleanState, null, 2));

  // 3. Create test directory with test files
  console.log('Creating test directory...');
  fs.mkdirSync(TEST_DIR, { recursive: true });
  fs.writeFileSync(path.join(TEST_DIR, 'test.txt'), 'Hello from SentinelGate E2E test!\n');
  fs.writeFileSync(path.join(TEST_DIR, 'secret.txt'), 'API_KEY=sk_live_abc123xyz\nDATABASE_URL=postgres://admin:password@db:5432\n');
  fs.writeFileSync(path.join(TEST_DIR, 'data.json'), JSON.stringify({ name: 'test', items: [1, 2, 3] }, null, 2));
  fs.mkdirSync(path.join(TEST_DIR, 'subdir'), { recursive: true });
  fs.writeFileSync(path.join(TEST_DIR, 'subdir', 'nested.txt'), 'Nested file content.\n');

  // 4. Clean recordings directory
  const recDir = path.join(fs.realpathSync('/tmp'), 'sg-recordings');
  if (fs.existsSync(recDir)) {
    fs.rmSync(recDir, { recursive: true, force: true });
  }
  fs.mkdirSync(recDir, { recursive: true });

  // 5. Start SentinelGate server (production mode — no --dev)
  console.log('Starting SentinelGate server...');
  serverProcess = spawn(BINARY, ['start'], {
    cwd: ROOT,
    env: { ...process.env, FORCE_COLOR: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Capture server logs
  const logFile = path.join(ROOT, 'tests', 'e2e', 'server.log');
  const logStream = fs.createWriteStream(logFile, { flags: 'w' });
  serverProcess.stdout?.pipe(logStream);
  serverProcess.stderr?.pipe(logStream);

  serverProcess.on('error', (err) => {
    console.error('Server process error:', err.message);
  });
  serverProcess.on('exit', (code) => {
    if (code !== null && code !== 0) {
      console.error(`Server exited with code ${code}`);
    }
  });

  // Store PID for teardown
  const pidFile = path.join(ROOT, 'tests', 'e2e', '.server-pid');
  fs.writeFileSync(pidFile, String(serverProcess.pid));

  // 6. Wait for server to be ready
  console.log('Waiting for server to be ready...');
  await waitForServer('http://localhost:8080/health');
  console.log('Server is ready!');

  // 7. Add upstream MCP servers via admin API (with CSRF)
  console.log('Configuring upstream MCP servers...');

  // Add filesystem upstream
  console.log('  Adding filesystem upstream...');
  const fsUpstream = await adminRequest('POST', '/upstreams', {
    name: 'filesystem',
    type: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-filesystem', TEST_DIR],
    enabled: true,
  });
  console.log(`  Filesystem upstream: ${fsUpstream?.id || 'FAILED'}`);

  // Add memory upstream
  console.log('  Adding memory upstream...');
  const memUpstream = await adminRequest('POST', '/upstreams', {
    name: 'memory',
    type: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-memory'],
    enabled: true,
  });
  console.log(`  Memory upstream: ${memUpstream?.id || 'FAILED'}`);

  // Wait for tool discovery (upstreams need time to connect and discover tools)
  console.log('Waiting for tool discovery...');
  let toolCount = 0;
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 1000));
    try {
      const toolsCheck = await new Promise<string>((resolve, reject) => {
        http.get('http://localhost:8080/admin/api/tools', (res) => {
          let body = '';
          res.on('data', (chunk) => body += chunk);
          res.on('end', () => resolve(body));
        }).on('error', reject);
      });
      const toolsData = JSON.parse(toolsCheck);
      toolCount = toolsData.tools?.length || 0;
      if (toolCount > 0) {
        console.log(`  Tools discovered: ${toolCount} (after ${i + 1}s)`);
        break;
      }
    } catch { /* retry */ }
  }
  if (toolCount === 0) {
    console.warn('  WARNING: No tools discovered after 30s!');
  }

  // 8. Create test identity and API key
  console.log('Creating test identity and API key...');
  const identity = await adminRequest('POST', '/identities', {
    name: 'e2e-tester',
    roles: ['admin', 'user'],
  });
  console.log(`  Identity created: ${identity.id}`);

  const keyResult = await adminRequest('POST', '/keys', {
    identity_id: identity.id,
    name: 'e2e-test-key',
  });
  console.log(`  API key created: ${keyResult.cleartext_key?.substring(0, 12)}...`);

  if (!keyResult.cleartext_key) {
    throw new Error('Failed to create API key — global setup cannot continue');
  }

  // Save key and identity for tests
  const envFile = path.join(ROOT, 'tests', 'e2e', '.env.test');
  fs.writeFileSync(envFile, [
    `API_KEY=${keyResult.cleartext_key}`,
    `IDENTITY_ID=${identity.id}`,
    `IDENTITY_NAME=e2e-tester`,
    `BASE_URL=http://localhost:8080`,
    `TEST_DIR=${TEST_DIR}`,
  ].join('\n'));

  console.log('\n=== Global Setup Complete ===\n');
}
