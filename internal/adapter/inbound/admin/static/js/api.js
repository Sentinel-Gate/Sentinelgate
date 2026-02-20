/**
 * api.js — Fetch wrapper for SentinelGate admin API.
 *
 * Provides SG.api with standardized JSON communication:
 *   - Automatic Content-Type and credentials
 *   - 401/403 handling for localhost-only access
 *   - Error extraction from response body
 *   - Convenience methods: get, post, put, del
 *
 * Usage:
 *   var data = await SG.api.get('/upstreams');
 *   await SG.api.post('/upstreams', { name: 'my-server', ... });
 *   await SG.api.del('/upstreams/abc123');
 */
'use strict';

window.SG = window.SG || {};

(function () {
  var BASE = '/admin/api';

  /**
   * Core fetch wrapper.
   *
   * @param {string} path     - API path relative to /admin/api (e.g. '/upstreams')
   * @param {Object} [options] - Fetch options override
   * @returns {Promise<*>} Parsed JSON response or null for 204
   * @throws {Error} With server error message or HTTP status fallback
   */
  /**
   * Read the CSRF token from the sentinel_csrf_token cookie.
   * Returns empty string if the cookie is not set.
   */
  function getCSRFToken() {
    var match = document.cookie.match(/sentinel_csrf_token=([^;]+)/);
    return match ? match[1] : '';
  }

  async function apiFetch(path, options) {
    var url = BASE + path;
    var opts = Object.assign({
      credentials: 'same-origin',
      headers: {}
    }, options || {});

    // Set JSON content type for requests with a body
    if (opts.body && !opts.headers['Content-Type']) {
      opts.headers['Content-Type'] = 'application/json';
    }

    // Include CSRF token on state-changing requests (SECU-02)
    var method = (opts.method || 'GET').toUpperCase();
    if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
      opts.headers['X-CSRF-Token'] = getCSRFToken();
    }

    var response;
    try {
      response = await fetch(url, opts);
    } catch (err) {
      throw new Error('Network error: ' + err.message);
    }

    // 401/403 — admin UI requires localhost access
    if (response.status === 401 || response.status === 403) {
      var err = new Error('Admin UI requires localhost access');
      err.status = response.status;
      throw err;
    }

    // 204 No Content
    if (response.status === 204) {
      return null;
    }

    // Try to parse JSON body
    var body;
    try {
      body = await response.json();
    } catch (e) {
      if (!response.ok) {
        throw new Error('HTTP ' + response.status);
      }
      return null;
    }

    // Non-2xx with parsed body — extract error message
    if (!response.ok) {
      var message = (body && body.error) ? body.error : 'HTTP ' + response.status;
      var err = new Error(message);
      err.status = response.status;
      err.body = body;
      throw err;
    }

    return body;
  }

  SG.api = {
    BASE: BASE,

    /** Raw fetch wrapper — use convenience methods when possible. */
    fetch: apiFetch,

    /** GET request. */
    get: function (path) {
      return apiFetch(path, { method: 'GET' });
    },

    /** POST request with JSON body. */
    post: function (path, data) {
      return apiFetch(path, {
        method: 'POST',
        body: data != null ? JSON.stringify(data) : undefined
      });
    },

    /** PUT request with JSON body. */
    put: function (path, data) {
      return apiFetch(path, {
        method: 'PUT',
        body: data != null ? JSON.stringify(data) : undefined
      });
    },

    /** DELETE request. */
    del: function (path, data) {
      return apiFetch(path, {
        method: 'DELETE',
        body: data != null ? JSON.stringify(data) : undefined
      });
    }
  };
})();
