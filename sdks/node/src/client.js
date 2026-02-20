'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const {
  PolicyDeniedError,
  ApprovalTimeoutError,
  ServerUnreachableError,
} = require('./errors');

/**
 * Client for the SentinelGate Policy Decision API.
 *
 * Evaluates actions against policies and returns structured decisions.
 * Uses only Node.js stdlib (no third-party dependencies).
 */
class SentinelGateClient {
  /**
   * @param {Object} [options]
   * @param {string} [options.serverAddr] - Server address. Defaults to SENTINELGATE_SERVER_ADDR env.
   * @param {string} [options.apiKey] - API key. Defaults to SENTINELGATE_API_KEY env.
   * @param {string} [options.defaultProtocol] - Protocol string. Defaults to "sdk".
   * @param {string} [options.failMode] - "open" or "closed". Defaults to SENTINELGATE_FAIL_MODE env or "open".
   * @param {number} [options.timeout] - Request timeout in ms. Defaults to 5000.
   * @param {number} [options.cacheTTL] - Cache TTL in ms. Defaults to SENTINELGATE_CACHE_TTL * 1000 or 5000.
   * @param {number} [options.cacheMaxSize] - Max cache entries. Defaults to 1000.
   */
  constructor(options = {}) {
    this._serverAddr = (
      options.serverAddr || process.env.SENTINELGATE_SERVER_ADDR || ''
    ).replace(/\/+$/, '');
    this._apiKey = options.apiKey || process.env.SENTINELGATE_API_KEY || '';
    this._defaultProtocol = options.defaultProtocol || 'sdk';
    this._failMode =
      options.failMode || process.env.SENTINELGATE_FAIL_MODE || 'open';
    this._timeout = options.timeout != null ? options.timeout : 5000;

    const cacheTTL = options.cacheTTL != null
      ? options.cacheTTL
      : parseInt(process.env.SENTINELGATE_CACHE_TTL || '5', 10) * 1000;
    this._cacheTTL = cacheTTL;
    this._cacheMaxSize = options.cacheMaxSize || 1000;

    // LRU cache using Map (insertion order preserved)
    this._cache = new Map();
  }

  /**
   * Evaluate an action against the Policy Decision API.
   *
   * @param {string} actionType - Action type (e.g. "command_exec", "http_request").
   * @param {string} actionName - Action name (e.g. command name, HTTP method).
   * @param {Object} [options]
   * @param {Object} [options.arguments] - Action arguments dict.
   * @param {Object} [options.destination] - Destination dict.
   * @param {string} [options.identityName] - Identity name. Defaults to SENTINELGATE_IDENTITY_NAME env or "sdk-client".
   * @param {string[]} [options.identityRoles] - Identity roles. Defaults to SENTINELGATE_IDENTITY_ROLES env or ["agent"].
   * @param {string} [options.protocol] - Protocol override.
   * @param {string} [options.framework] - Framework hint.
   * @param {boolean} [options.raiseOnDeny=true] - Throw PolicyDeniedError on deny.
   * @returns {Promise<Object>} Response with decision, ruleId, ruleName, reason, helpUrl, helpText, requestId, latencyMs.
   */
  async evaluate(actionType, actionName, options = {}) {
    const {
      arguments: args,
      destination,
      identityName,
      identityRoles,
      protocol,
      framework,
      raiseOnDeny = true,
    } = options;

    // Resolve identity defaults
    const resolvedIdentityName =
      identityName ||
      process.env.SENTINELGATE_IDENTITY_NAME ||
      'sdk-client';

    let resolvedIdentityRoles = identityRoles;
    if (!resolvedIdentityRoles) {
      const rolesEnv = process.env.SENTINELGATE_IDENTITY_ROLES || '';
      if (rolesEnv) {
        resolvedIdentityRoles = rolesEnv
          .split(',')
          .map((r) => r.trim())
          .filter(Boolean);
      } else {
        resolvedIdentityRoles = ['agent'];
      }
    }

    const proto = protocol || this._defaultProtocol;

    // Check LRU cache
    const cacheKey = this._cacheKey(actionType, actionName, args);
    const cached = this._cacheGet(cacheKey);
    if (cached) {
      return cached;
    }

    // Build request body matching PolicyEvaluateRequest schema
    const body = {
      action_type: actionType,
      action_name: actionName,
      protocol: proto,
      identity_name: resolvedIdentityName,
      identity_roles: resolvedIdentityRoles,
    };
    if (framework) body.framework = framework;
    if (args) body.arguments = args;
    if (destination) body.destination = destination;

    // Send request
    let respData;
    try {
      respData = await this._httpPost(
        `${this._serverAddr}/admin/api/v1/policy/evaluate`,
        body
      );
    } catch (err) {
      if (this._failMode === 'closed') {
        throw new ServerUnreachableError(
          `SentinelGate server unreachable: ${err.message}`
        );
      }
      console.warn(
        `SentinelGate: Policy evaluation failed (${err.message}), allowing action (fail-open)`
      );
      return {
        decision: 'allow',
        reason: 'fail-open',
        ruleId: '',
        ruleName: '',
        helpUrl: '',
        helpText: '',
        requestId: '',
        latencyMs: 0,
      };
    }

    // Normalize response keys to camelCase for SDK consumers
    const result = this._normalizeResponse(respData);
    const decision = result.decision;

    // Handle approval_required by polling status endpoint
    if (decision === 'approval_required') {
      const requestId = result.requestId;
      if (requestId) {
        return this._pollApproval(requestId, result, raiseOnDeny);
      }
      return result;
    }

    // Cache allow decisions
    if (decision === 'allow') {
      this._cacheSet(cacheKey, result);
    }

    // Throw on deny if configured
    if (decision === 'deny' && raiseOnDeny) {
      throw new PolicyDeniedError(`Policy denied: ${result.reason}`, {
        ruleId: result.ruleId,
        ruleName: result.ruleName,
        reason: result.reason,
        helpUrl: result.helpUrl,
        helpText: result.helpText,
      });
    }

    return result;
  }

  /**
   * Check if an action is allowed without throwing exceptions.
   *
   * @param {string} actionType - Action type.
   * @param {string} actionName - Action name.
   * @param {Object} [options] - Same as evaluate() options.
   * @returns {Promise<boolean>} True if allowed, false if denied.
   */
  async check(actionType, actionName, options = {}) {
    try {
      const result = await this.evaluate(actionType, actionName, {
        ...options,
        raiseOnDeny: false,
      });
      return result.decision === 'allow';
    } catch (err) {
      // On any error, return true (fail-open behavior for check)
      return true;
    }
  }

  // -- Approval Polling -------------------------------------------------------

  async _pollApproval(requestId, originalResponse, raiseOnDeny) {
    const maxPolls = 30;
    const pollInterval = 2000; // ms

    for (let i = 0; i < maxPolls; i++) {
      await this._sleep(pollInterval);

      try {
        const statusData = await this._httpGet(
          `${this._serverAddr}/admin/api/v1/policy/evaluate/${encodeURIComponent(requestId)}/status`
        );

        const status = statusData.status || '';

        if (status === 'approved' || status === 'allow') {
          return {
            decision: 'allow',
            reason: 'approved',
            requestId,
            ruleId: originalResponse.ruleId || '',
            ruleName: originalResponse.ruleName || '',
            helpUrl: '',
            helpText: '',
            latencyMs: originalResponse.latencyMs || 0,
          };
        }

        if (status === 'denied' || status === 'deny') {
          const result = {
            decision: 'deny',
            reason: statusData.reason || 'denied by reviewer',
            requestId,
            ruleId: originalResponse.ruleId || '',
            ruleName: originalResponse.ruleName || '',
            helpUrl: originalResponse.helpUrl || '',
            helpText: originalResponse.helpText || '',
            latencyMs: originalResponse.latencyMs || 0,
          };
          if (raiseOnDeny) {
            throw new PolicyDeniedError(`Policy denied: ${result.reason}`, {
              ruleId: result.ruleId,
              ruleName: result.ruleName,
              reason: result.reason,
              helpUrl: result.helpUrl,
              helpText: result.helpText,
            });
          }
          return result;
        }
        // Still pending, continue polling
      } catch (err) {
        if (err instanceof PolicyDeniedError) throw err;
        // Network error during polling; continue
      }
    }

    throw new ApprovalTimeoutError(
      `Approval timed out after ${(maxPolls * pollInterval) / 1000}s`,
      { requestId }
    );
  }

  // -- HTTP helpers -----------------------------------------------------------

  _httpPost(urlStr, body) {
    return new Promise((resolve, reject) => {
      try {
        const parsedUrl = new URL(urlStr);
        const postData = JSON.stringify(body);
        const transport = parsedUrl.protocol === 'https:' ? https : http;

        const options = {
          method: 'POST',
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
          timeout: this._timeout,
        };

        if (this._apiKey) {
          options.headers['Authorization'] = `Bearer ${this._apiKey}`;
        }

        const req = transport.request(options, (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(new Error(`Invalid JSON response: ${data}`));
            }
          });
        });

        req.on('error', reject);
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Request timed out'));
        });

        req.write(postData);
        req.end();
      } catch (err) {
        reject(err);
      }
    });
  }

  _httpGet(urlStr) {
    return new Promise((resolve, reject) => {
      try {
        const parsedUrl = new URL(urlStr);
        const transport = parsedUrl.protocol === 'https:' ? https : http;

        const options = {
          method: 'GET',
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          timeout: this._timeout,
        };

        if (this._apiKey) {
          options.headers = { Authorization: `Bearer ${this._apiKey}` };
        }

        const req = transport.request(options, (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(new Error(`Invalid JSON response: ${data}`));
            }
          });
        });

        req.on('error', reject);
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Request timed out'));
        });

        req.end();
      } catch (err) {
        reject(err);
      }
    });
  }

  // -- Response normalization ------------------------------------------------

  _normalizeResponse(data) {
    return {
      decision: data.decision || 'allow',
      ruleId: data.rule_id || '',
      ruleName: data.rule_name || '',
      reason: data.reason || '',
      helpUrl: data.help_url || '',
      helpText: data.help_text || '',
      requestId: data.request_id || '',
      latencyMs: data.latency_ms || 0,
    };
  }

  // -- Cache helpers ---------------------------------------------------------

  _cacheKey(actionType, actionName, args) {
    return `${actionType}:${actionName}:${JSON.stringify(args || {})}`;
  }

  _cacheGet(key) {
    const entry = this._cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > this._cacheTTL) {
      this._cache.delete(key);
      return null;
    }
    // Move to end (most recently used)
    this._cache.delete(key);
    this._cache.set(key, entry);
    return entry.value;
  }

  _cacheSet(key, value) {
    this._cache.delete(key);
    if (this._cache.size >= this._cacheMaxSize) {
      const firstKey = this._cache.keys().next().value;
      this._cache.delete(firstKey);
    }
    this._cache.set(key, { value, ts: Date.now() });
  }

  // -- Utility ---------------------------------------------------------------

  _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

module.exports = SentinelGateClient;
