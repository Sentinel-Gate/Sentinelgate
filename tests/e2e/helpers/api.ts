import { APIRequestContext, Page } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

const ENV_FILE = path.resolve(__dirname, '..', '.env.test');

export interface TestEnv {
  apiKey: string;
  identityId: string;
  identityName: string;
  baseUrl: string;
  testDir: string;
}

let cachedEnv: TestEnv | null = null;

export function getTestEnv(): TestEnv {
  if (cachedEnv) return cachedEnv;

  const content = fs.readFileSync(ENV_FILE, 'utf-8');
  const vars: Record<string, string> = {};
  for (const line of content.split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) {
      vars[line.substring(0, eq)] = line.substring(eq + 1);
    }
  }

  cachedEnv = {
    apiKey: vars.API_KEY || '',
    identityId: vars.IDENTITY_ID || '',
    identityName: vars.IDENTITY_NAME || 'e2e-tester',
    baseUrl: vars.BASE_URL || 'http://localhost:8080',
    testDir: vars.TEST_DIR || '/tmp/sg-e2e-test',
  };
  return cachedEnv;
}

/**
 * Admin API helper — calls the admin API (no auth needed from localhost).
 * Handles CSRF token automatically for mutating requests.
 */
export class AdminAPI {
  private csrfTokenCache: string | null = null;

  constructor(private request: APIRequestContext) {}

  private async getCSRFToken(): Promise<string> {
    // Return cached token if available (avoids cookie jar pollution
    // where subsequent GETs don't get a new Set-Cookie header because
    // the jar already sends the old cookie).
    if (this.csrfTokenCache) return this.csrfTokenCache;

    // GET /admin/ does NOT go through CSRF middleware (only cspMiddleware),
    // so it won't set a sentinel_csrf_token cookie. Instead, hit an API GET
    // endpoint which DOES go through csrfMiddleware and calls ensureCSRFCookie().
    const res = await this.request.get('/admin/api/tools');
    const cookies = res.headers()['set-cookie'] || '';
    const match = cookies.match(/sentinel_csrf_token=([^;]+)/);
    if (match) {
      this.csrfTokenCache = match[1];
      return this.csrfTokenCache;
    }
    return '';
  }

  async get(path: string) {
    const res = await this.request.get(`/admin/api${path}`);
    if (res.status() === 204) return null;
    return res.json();
  }

  async post(path: string, data?: any) {
    const csrf = await this.getCSRFToken();
    const res = await this.request.post(`/admin/api${path}`, {
      data,
      headers: { 'X-CSRF-Token': csrf },
    });
    if (res.status() === 204) return null;
    return res.json();
  }

  async put(path: string, data?: any) {
    const csrf = await this.getCSRFToken();
    const res = await this.request.put(`/admin/api${path}`, {
      data,
      headers: { 'X-CSRF-Token': csrf },
    });
    if (res.status() === 204) return null;
    return res.json();
  }

  async del(path: string) {
    const csrf = await this.getCSRFToken();
    const res = await this.request.delete(`/admin/api${path}`, {
      headers: { 'X-CSRF-Token': csrf },
    });
    if (res.status() === 204) return null;
    try { return await res.json(); } catch { return null; }
  }

  async getRaw(path: string) {
    return this.request.get(`/admin/api${path}`);
  }

  async postRaw(path: string, data?: any) {
    const csrf = await this.getCSRFToken();
    return this.request.post(`/admin/api${path}`, {
      data,
      headers: { 'X-CSRF-Token': csrf },
    });
  }

  // Convenience methods

  async getStats() { return this.get('/stats'); }
  async getUpstreams() { return this.get('/upstreams'); }
  async getTools() { return this.get('/tools'); }
  async getPolicies() { return this.get('/policies'); }
  async getIdentities() { return this.get('/identities'); }
  async getKeys() { return this.get('/keys'); }
  async getActiveSessions() { return this.get('/v1/sessions/active'); }
  async getQuotas() { return this.get('/v1/quotas'); }
  async getTransforms() { return this.get('/v1/transforms'); }
  async getRecordings() { return this.get('/v1/recordings'); }
  async getApprovals() { return this.get('/v1/approvals'); }
  async getContentScanning() { return this.get('/v1/security/content-scanning'); }
  async getOutboundRules() { return this.get('/v1/security/outbound/rules'); }
  async getQuarantined() { return this.get('/v1/tools/quarantine'); }
  async getAudit(params = '') { return this.get(`/audit${params ? '?' + params : ''}`); }

  async createUpstream(data: { name: string; type: string; command?: string; args?: string[]; url?: string; enabled?: boolean }) {
    return this.post('/upstreams', { enabled: true, ...data });
  }

  async deleteUpstream(id: string) { return this.del(`/upstreams/${id}`); }

  async createPolicy(data: { name: string; description?: string; priority?: number; enabled?: boolean; rules?: any[] }) {
    return this.post('/policies', { priority: 100, enabled: true, ...data });
  }

  async deletePolicy(id: string) { return this.del(`/policies/${id}`); }

  async createIdentity(data: { name: string; roles?: string[] }) {
    return this.post('/identities', { roles: ['user'], ...data });
  }

  async deleteIdentity(id: string) { return this.del(`/identities/${id}`); }

  async createKey(identityId: string, name: string) {
    return this.post('/keys', { identity_id: identityId, name });
  }

  async revokeKey(id: string) { return this.del(`/keys/${id}`); }

  async setQuota(identityId: string, data: any) {
    return this.put(`/v1/quotas/${identityId}`, data);
  }

  async deleteQuota(identityId: string) { return this.del(`/v1/quotas/${identityId}`); }

  async createTransform(data: any) { return this.post('/v1/transforms', data); }
  async deleteTransform(id: string) { return this.del(`/v1/transforms/${id}`); }

  async setRecordingConfig(data: any) { return this.put('/v1/recordings/config', data); }
  async setContentScanning(data: any) { return this.put('/v1/security/content-scanning', data); }

  async createOutboundRule(data: any) { return this.post('/v1/security/outbound/rules', data); }
  async deleteOutboundRule(id: string) { return this.del(`/v1/security/outbound/rules/${id}`); }

  async captureBaseline() { return this.post('/v1/tools/baseline'); }
  async quarantineTool(toolName: string) { return this.post('/v1/tools/quarantine', { tool_name: toolName }); }
  async unquarantineTool(toolName: string) { return this.del(`/v1/tools/quarantine/${toolName}`); }

  async approveRequest(id: string) { return this.post(`/v1/approvals/${id}/approve`); }
  async denyRequest(id: string, reason?: string) { return this.post(`/v1/approvals/${id}/deny`, reason ? { reason } : undefined); }

  async refreshTools() { return this.post('/tools/refresh'); }
}

/**
 * Wait for a condition with polling.
 */
export async function waitFor(
  fn: () => Promise<boolean>,
  opts: { timeout?: number; interval?: number; message?: string } = {}
): Promise<void> {
  const { timeout = 10_000, interval = 500, message = 'Condition not met' } = opts;
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (await fn()) return;
    await new Promise(r => setTimeout(r, interval));
  }
  throw new Error(`Timeout: ${message}`);
}
