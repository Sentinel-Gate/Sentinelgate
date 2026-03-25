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
    const setCookie = res.headers()['set-cookie'] || '';
    const match = setCookie.match(/sentinel_csrf_token=([^;]+)/);
    if (match) {
      this.csrfTokenCache = match[1];
      return this.csrfTokenCache;
    }

    // If Set-Cookie was absent (cookie already in jar from a prior request
    // context, e.g. beforeAll), read the token from the Playwright storage
    // state which contains the full cookie jar.
    try {
      const state = await this.request.storageState();
      const csrfCookie = state.cookies.find(
        (c: any) => c.name === 'sentinel_csrf_token',
      );
      if (csrfCookie) {
        this.csrfTokenCache = csrfCookie.value;
        return this.csrfTokenCache;
      }
    } catch {
      // storageState() may not be available in all contexts; fall through
    }

    return '';
  }

  /** Throw on non-2xx responses (except 429 which is retried, and 204 which returns null). */
  private async assertOk(res: { status(): number; text(): Promise<string> }, context: string): Promise<void> {
    const status = res.status();
    if (status >= 200 && status < 300) return;
    const body = await res.text().catch(() => '<unable to read body>');
    throw new Error(`AdminAPI ${context} failed with status ${status}: ${body}`);
  }

  /** Retry a request up to 3 times on 429 (rate limit) with exponential backoff. */
  private async withRetry<T>(fn: () => Promise<T>, isRaw = false): Promise<T> {
    for (let attempt = 0; attempt < 4; attempt++) {
      const result = await fn();
      // For raw responses, check status directly
      if (isRaw) {
        const res = result as any;
        if (res.status && res.status() === 429 && attempt < 3) {
          await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
          continue;
        }
        return result;
      }
      return result;
    }
    return fn();
  }

  async get(path: string) {
    return this.withRetry(async () => {
      const res = await this.request.get(`/admin/api${path}`);
      if (res.status() === 429) throw { status: 429 };
      if (res.status() === 204) return null;
      // GET requests should NOT throw on non-2xx — many endpoints legitimately
      // return 4xx/5xx for unconfigured features (finops, sessions, recordings).
      // Return the parsed JSON (which may contain an "error" field) so tests
      // can inspect it, or null if the body is not valid JSON.
      if (res.status() >= 400) {
        try { return await res.json(); } catch { return null; }
      }
      return res.json();
    }).catch(async (e) => {
      if (e?.status === 429) {
        await new Promise(r => setTimeout(r, 2000));
        const res = await this.request.get(`/admin/api${path}`);
        if (res.status() === 204) return null;
        if (res.status() >= 400) {
          try { return await res.json(); } catch { return null; }
        }
        return res.json();
      }
      throw e;
    });
  }

  async post(path: string, data?: any) {
    return this.withRetry(async () => {
      const csrf = await this.getCSRFToken();
      const res = await this.request.post(`/admin/api${path}`, {
        data,
        headers: { 'X-CSRF-Token': csrf },
      });
      if (res.status() === 429) throw { status: 429 };
      // On CSRF failure, clear cached token and retry once with a fresh one
      if (res.status() === 403) {
        this.csrfTokenCache = null;
        const freshCsrf = await this.getCSRFToken();
        const retryRes = await this.request.post(`/admin/api${path}`, {
          data,
          headers: { 'X-CSRF-Token': freshCsrf },
        });
        if (retryRes.status() === 204) return null;
        await this.assertOk(retryRes, `POST ${path}`);
        return retryRes.json();
      }
      if (res.status() === 204) return null;
      await this.assertOk(res, `POST ${path}`);
      return res.json();
    }).catch(async (e) => {
      if (e?.status === 429) {
        await new Promise(r => setTimeout(r, 2000));
        this.csrfTokenCache = null;
        const csrf = await this.getCSRFToken();
        const res = await this.request.post(`/admin/api${path}`, {
          data,
          headers: { 'X-CSRF-Token': csrf },
        });
        if (res.status() === 204) return null;
        await this.assertOk(res, `POST ${path}`);
        return res.json();
      }
      throw e;
    });
  }

  async put(path: string, data?: any) {
    return this.withRetry(async () => {
      const csrf = await this.getCSRFToken();
      const res = await this.request.put(`/admin/api${path}`, {
        data,
        headers: { 'X-CSRF-Token': csrf },
      });
      if (res.status() === 429) throw { status: 429 };
      // On CSRF failure, clear cached token and retry once with a fresh one
      if (res.status() === 403) {
        this.csrfTokenCache = null;
        const freshCsrf = await this.getCSRFToken();
        const retryRes = await this.request.put(`/admin/api${path}`, {
          data,
          headers: { 'X-CSRF-Token': freshCsrf },
        });
        if (retryRes.status() === 204) return null;
        await this.assertOk(retryRes, `PUT ${path}`);
        return retryRes.json();
      }
      if (res.status() === 204) return null;
      await this.assertOk(res, `PUT ${path}`);
      return res.json();
    }).catch(async (e) => {
      if (e?.status === 429) {
        await new Promise(r => setTimeout(r, 2000));
        this.csrfTokenCache = null;
        const csrf = await this.getCSRFToken();
        const res = await this.request.put(`/admin/api${path}`, {
          data,
          headers: { 'X-CSRF-Token': csrf },
        });
        if (res.status() === 204) return null;
        await this.assertOk(res, `PUT ${path}`);
        return res.json();
      }
      throw e;
    });
  }

  async del(path: string) {
    return this.withRetry(async () => {
      const csrf = await this.getCSRFToken();
      const res = await this.request.delete(`/admin/api${path}`, {
        headers: { 'X-CSRF-Token': csrf },
      });
      if (res.status() === 429) throw { status: 429 };
      // On CSRF failure, clear cached token and retry once with a fresh one
      if (res.status() === 403) {
        this.csrfTokenCache = null;
        const freshCsrf = await this.getCSRFToken();
        const retryRes = await this.request.delete(`/admin/api${path}`, {
          headers: { 'X-CSRF-Token': freshCsrf },
        });
        if (retryRes.status() === 204) return null;
        await this.assertOk(retryRes, `DELETE ${path}`);
        try { return await retryRes.json(); } catch { return null; }
      }
      if (res.status() === 204) return null;
      await this.assertOk(res, `DELETE ${path}`);
      try { return await res.json(); } catch { return null; }
    }).catch(async (e) => {
      if (e?.status === 429) {
        await new Promise(r => setTimeout(r, 2000));
        this.csrfTokenCache = null;
        const csrf = await this.getCSRFToken();
        const res = await this.request.delete(`/admin/api${path}`, {
          headers: { 'X-CSRF-Token': csrf },
        });
        if (res.status() === 204) return null;
        await this.assertOk(res, `DELETE ${path}`);
        try { return await res.json(); } catch { return null; }
      }
      throw e;
    });
  }

  async getRaw(path: string) {
    for (let attempt = 0; attempt < 3; attempt++) {
      const res = await this.request.get(`/admin/api${path}`);
      if (res.status() !== 429) return res;
      await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
    }
    return this.request.get(`/admin/api${path}`);
  }

  async postRaw(path: string, data?: any) {
    for (let attempt = 0; attempt < 3; attempt++) {
      const csrf = await this.getCSRFToken();
      const res = await this.request.post(`/admin/api${path}`, {
        data,
        headers: { 'X-CSRF-Token': csrf },
      });
      if (res.status() !== 429) return res;
      await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
    }
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

  async captureBaseline() { return this.post('/v1/tools/baseline'); }
  async quarantineTool(toolName: string) { return this.post('/v1/tools/quarantine', { tool_name: toolName }); }
  async unquarantineTool(toolName: string) { return this.del(`/v1/tools/quarantine/${toolName}`); }

  async approveRequest(id: string) { return this.post(`/v1/approvals/${id}/approve`); }
  async denyRequest(id: string, reason?: string) { return this.post(`/v1/approvals/${id}/deny`, reason ? { reason } : undefined); }

  async refreshTools() { return this.post('/tools/refresh'); }

  // Policy management
  async updatePolicy(id: string, data: any) { return this.put(`/policies/${id}`, data); }
  async testPolicy(data: any) { return this.post('/policies/test', data); }
  async lintPolicy(data: any) { return this.post('/policies/lint', data); }
  async deleteRule(policyId: string, ruleId: string) { return this.del(`/policies/${policyId}/rules/${ruleId}`); }

  // Identity updates
  async updateIdentity(id: string, data: any) { return this.put(`/identities/${id}`, data); }

  // Upstream updates & lifecycle
  async updateUpstream(id: string, data: any) { return this.put(`/upstreams/${id}`, data); }
  async restartUpstream(id: string) { return this.post(`/upstreams/${id}/restart`); }

  // Policy templates
  async listTemplates() { return this.get('/v1/templates'); }
  async getTemplate(id: string) { return this.get(`/v1/templates/${id}`); }
  async applyTemplate(id: string, data?: any) { return this.post(`/v1/templates/${id}/apply`, data); }

  // Input scanning
  async getInputScanning() { return this.get('/v1/security/input-scanning'); }
  async setInputScanning(data: any) { return this.put('/v1/security/input-scanning', data); }

  // Notifications
  async getNotifications() { return this.get('/v1/notifications'); }
  async getNotificationCount() { return this.get('/v1/notifications/count'); }
  async dismissNotification(id: string) { return this.post(`/v1/notifications/${id}/dismiss`); }
  async dismissAllNotifications() { return this.post('/v1/notifications/dismiss-all'); }

  // Drift detection
  async getDriftReports() { return this.get('/v1/drift/reports'); }
  async getDriftConfig() { return this.get('/v1/drift/config'); }
  async setDriftConfig(data: any) { return this.put('/v1/drift/config', data); }

  // Red team
  async runRedTeam(data: any) { return this.post('/v1/redteam/run', data); }
  async runSingleRedTeam(data: any) { return this.post('/v1/redteam/run/single', data); }
  async getRedTeamCorpus() { return this.get('/v1/redteam/corpus'); }
  async getRedTeamReports() { return this.get('/v1/redteam/reports'); }

  // Policy simulation
  async runSimulation(data: any) { return this.post('/v1/simulation/run', data); }

  // FinOps
  async getFinOpsCosts() { return this.get('/v1/finops/costs'); }
  async getFinOpsConfig() { return this.get('/v1/finops/config'); }
  async setFinOpsConfig(data: any) { return this.put('/v1/finops/config', data); }

  // Permission health
  async getPermissionHealth() { return this.get('/v1/permissions/health'); }
  async getPermissionConfig() { return this.get('/v1/permissions/config'); }
  async setPermissionConfig(data: any) { return this.put('/v1/permissions/config', data); }

  // Compliance
  async getCompliancePacks() { return this.get('/v1/compliance/packs'); }
  async getComplianceCoverage(packId: string) { return this.post(`/v1/compliance/packs/${packId}/coverage`); }
  async generateComplianceBundle(packId: string) { return this.post('/v1/compliance/bundles', { pack_id: packId }); }

  // Recording details
  async getRecording(id: string) { return this.get(`/v1/recordings/${id}`); }
  async getRecordingEvents(id: string) { return this.get(`/v1/recordings/${id}/events`); }
  async getRecordingConfig() { return this.get('/v1/recordings/config'); }
  async deleteRecording(id: string) { return this.del(`/v1/recordings/${id}`); }

  // Session management
  async terminateSession(id: string) { return this.del(`/v1/sessions/${id}`); }

  // Agent health
  async getAgentSummary(identityId: string) { return this.get(`/v1/agents/${identityId}/summary`); }
  async getHealthOverview() { return this.get('/v1/health/overview'); }

  // Tool drift
  async getBaseline() { return this.get('/v1/tools/baseline'); }
  async detectDrift() { return this.get('/v1/tools/drift'); }
  async acceptToolChange(data: any) { return this.post('/v1/tools/accept-change', data); }

  // System
  async getSystemInfo() { return this.get('/system'); }
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
