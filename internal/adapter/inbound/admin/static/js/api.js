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

  // -- Top progress bar state --
  var progressBar = null;
  var activeRequests = 0;
  var progressTimer = null;

  function getProgressBar() {
    if (!progressBar) {
      progressBar = document.createElement('div');
      progressBar.className = 'top-progress';
      document.body.appendChild(progressBar);
    }
    return progressBar;
  }

  function startProgress() {
    activeRequests++;
    if (activeRequests === 1) {
      var bar = getProgressBar();
      bar.className = 'top-progress';
      void bar.offsetWidth; // force reflow
      bar.classList.add('active');
    }
  }

  function endProgress() {
    activeRequests = Math.max(0, activeRequests - 1);
    if (activeRequests === 0) {
      var bar = getProgressBar();
      bar.classList.remove('active');
      bar.classList.add('complete');

      clearTimeout(progressTimer);
      progressTimer = setTimeout(function () {
        bar.classList.add('fade-out');
        setTimeout(function () {
          bar.className = 'top-progress';
        }, 300);
      }, 200);
    }
  }

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

    // -- Progress bar (skip for background/polling requests) --
    var silent = opts.silent;
    delete opts.silent;
    if (!silent) startProgress();

    var response;
    try {
      response = await fetch(url, opts);
    } catch (err) {
      if (!silent) endProgress();
      throw new Error('Network error: ' + err.message);
    }

    if (!silent) endProgress();

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

    /** GET request. Pass opts.silent to suppress progress bar. */
    get: function (path, opts) {
      return apiFetch(path, Object.assign({ method: 'GET' }, opts || {}));
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

  /**
   * Optimistic UI helper — wraps an API call with instant UI update + rollback.
   *
   * Usage:
   *   SG.optimistic({
   *     optimisticFn: function() {
   *       // Immediately update UI, return rollback data
   *       var row = addRowToTable(newRule);
   *       return { row: row, previousData: [...currentRules] };
   *     },
   *     apiFn: function() {
   *       return SG.api.post('/policies', newRule);
   *     },
   *     successFn: function(apiResult, rollbackData) {
   *       // Finalize with real server data
   *       rollbackData.row.dataset.id = apiResult.id;
   *       SG.toast.success('Rule created');
   *     },
   *     rollbackFn: function(error, rollbackData) {
   *       // Undo the optimistic update
   *       rollbackData.row.remove();
   *       currentRules = rollbackData.previousData;
   *       SG.toast.error('Failed: ' + error.message);
   *     }
   *   });
   *
   * @param {Object} opts
   * @param {Function} opts.optimisticFn - Runs immediately; returns rollback data
   * @param {Function} opts.apiFn        - Returns a Promise (the real API call)
   * @param {Function} opts.successFn    - Called with (apiResult, rollbackData) on success
   * @param {Function} opts.rollbackFn   - Called with (error, rollbackData) on failure
   */
  SG.optimistic = function (opts) {
    // Step 1: Apply optimistic update immediately
    var rollbackData;
    try {
      rollbackData = opts.optimisticFn();
    } catch (e) {
      // If optimistic update fails, don't even call the API
      if (opts.rollbackFn) opts.rollbackFn(e, null);
      return;
    }

    // Step 2: Fire the real API call
    opts.apiFn()
      .then(function (result) {
        // Step 3a: Success — finalize the optimistic update
        if (opts.successFn) opts.successFn(result, rollbackData);
      })
      .catch(function (err) {
        // Step 3b: Failure — rollback the optimistic update
        if (opts.rollbackFn) opts.rollbackFn(err, rollbackData);
      });
  };
})();
