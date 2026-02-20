// SentinelGate Node.js Runtime Hook
// Loaded via NODE_OPTIONS="--require /path/to/sentinelgate-hook.js"
// Intercepts child_process, fs, fetch, http/https to evaluate actions
// against the SentinelGate Policy Decision API before execution.
//
// No npm dependencies required. CommonJS only. Stdlib only.

(function _sentinelGateHook() {
  'use strict';

  // ── Configuration ──────────────────────────────────────────────────────────
  var _sgServerAddr = process.env.SENTINELGATE_SERVER_ADDR;
  var _sgApiKey = process.env.SENTINELGATE_API_KEY;
  var _sgAgentId = process.env.SENTINELGATE_AGENT_ID || 'unknown';
  var _sgCacheTTL = parseInt(process.env.SENTINELGATE_CACHE_TTL || '5', 10) * 1000; // ms

  // If no server address is configured, skip all instrumentation.
  if (!_sgServerAddr) {
    return;
  }

  // ── Save original references BEFORE patching ──────────────────────────────
  var _origChildProcess = {};
  var _cp = require('child_process');
  _origChildProcess.execFileSync = _cp.execFileSync;
  _origChildProcess.spawnSync = _cp.spawnSync;
  _origChildProcess.exec = _cp.exec;
  _origChildProcess.execSync = _cp.execSync;
  _origChildProcess.spawn = _cp.spawn;
  _origChildProcess.fork = _cp.fork;
  _origChildProcess.execFile = _cp.execFile;

  var _origHttp = require('http');
  var _origHttps = require('https');
  var _origHttpRequest = _origHttp.request;
  var _origHttpsRequest = _origHttps.request;

  // ── Fail Mode & Framework Detection ────────────────────────────────────────
  var _sgFailMode = process.env.SENTINELGATE_FAIL_MODE || 'open';

  function _sgDetectFramework() {
    // Try to detect installed AI frameworks via require.resolve.
    try { require.resolve('langchain'); return 'langchain'; } catch (e) {}
    try { require.resolve('crewai'); return 'crewai'; } catch (e) {}
    try { require.resolve('autogen'); return 'autogen'; } catch (e) {}
    try { require.resolve('@openai/agents'); return 'openai-agents-sdk'; } catch (e) {}
    try { require.resolve('openai-agents'); return 'openai-agents-sdk'; } catch (e) {}

    // Fall back to env var hint from Go-side detection.
    return process.env.SENTINELGATE_FRAMEWORK || '';
  }

  var _sgFramework = _sgDetectFramework();

  // ── Recursion Guard ────────────────────────────────────────────────────────
  // Prevents infinite loops when evaluation itself makes child_process/HTTP calls.
  var _sgInEvaluation = false;

  // ── LRU Cache ──────────────────────────────────────────────────────────────
  // Uses Map (insertion-ordered in JS) for O(1) operations with TTL.
  function _SgLRUCache(maxSize, ttlMs) {
    this._maxSize = maxSize || 1000;
    this._ttlMs = ttlMs || 5000;
    this._map = new Map();
  }

  _SgLRUCache.prototype.get = function(key) {
    var entry = this._map.get(key);
    if (!entry) return null;
    // Check expiry.
    if (Date.now() - entry.ts > this._ttlMs) {
      this._map.delete(key);
      return null;
    }
    // Move to end (most recently used).
    this._map.delete(key);
    this._map.set(key, entry);
    return entry.value;
  };

  _SgLRUCache.prototype.set = function(key, value) {
    // Remove existing to reset position.
    this._map.delete(key);
    // Evict oldest if at capacity.
    if (this._map.size >= this._maxSize) {
      var firstKey = this._map.keys().next().value;
      this._map.delete(firstKey);
    }
    this._map.set(key, { value: value, ts: Date.now() });
  };

  var _sgCache = new _SgLRUCache(1000, _sgCacheTTL);

  // ── Audit Buffer ───────────────────────────────────────────────────────────
  // Stores events locally when SentinelGate server is unreachable, syncs on reconnect.
  function _SgAuditBuffer(maxSize) {
    this._maxSize = maxSize || 500;
    this._buffer = [];
    this._flushing = false;
  }

  _SgAuditBuffer.prototype.add = function(event) {
    this._buffer.push(event);
    if (this._buffer.length > this._maxSize) {
      this._buffer.shift();
    }
  };

  _SgAuditBuffer.prototype.flush = function() {
    if (this._flushing || this._buffer.length === 0) return;
    this._flushing = true;

    var events = this._buffer.slice();
    var self = this;

    try {
      var url = new URL(_sgServerAddr + '/admin/api/v1/audit/events');
      var postData = JSON.stringify({ events: events });
      var options = {
        method: 'POST',
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      };
      if (_sgApiKey) {
        options.headers['Authorization'] = 'Bearer ' + _sgApiKey;
      }

      var transport = url.protocol === 'https:' ? _origHttps : _origHttp;
      var req = (transport === _origHttps ? _origHttpsRequest : _origHttpRequest).call(transport, options, function(res) {
        var data = '';
        res.on('data', function(c) { data += c; });
        res.on('end', function() {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            // Successfully flushed; clear buffer.
            self._buffer = self._buffer.slice(events.length);
          }
          self._flushing = false;
        });
      });
      req.on('error', function() { self._flushing = false; });
      req.write(postData);
      req.end();
    } catch (e) {
      this._flushing = false;
    }
  };

  var _sgAuditBuffer = new _SgAuditBuffer(500);

  // ── Synchronous Policy Evaluation ──────────────────────────────────────────
  // Uses spawnSync to make blocking HTTP requests so actions are evaluated
  // BEFORE execution. This is the standard pattern for synchronous HTTP in
  // Node.js --require hooks.

  function _sgEvaluateSync(actionType, actionName, args, destination) {
    // Build cache key.
    var cacheKey = actionType + ':' + actionName + ':' + JSON.stringify(args || {});
    var cached = _sgCache.get(cacheKey);
    if (cached) return cached;

    // Build request body matching PolicyEvaluateRequest.
    var body = {
      action_type: actionType,
      action_name: actionName,
      protocol: 'runtime',
      framework: _sgFramework,
      gateway: 'runtime',
      arguments: args || {},
      identity_name: 'runtime-' + _sgAgentId,
      identity_roles: ['agent']
    };
    if (destination) {
      body.destination = destination;
    }

    try {
      _sgInEvaluation = true;

      var bodyStr = JSON.stringify(body);
      // Build an inline Node.js script for synchronous HTTP POST.
      var scriptCode =
        'var http = require("http");' +
        'var https = require("https");' +
        'var url = new URL("' + _sgServerAddr.replace(/"/g, '\\"') + '/admin/api/v1/policy/evaluate");' +
        'var postData = ' + JSON.stringify(bodyStr) + ';' +
        'var options = {' +
        '  method: "POST",' +
        '  hostname: url.hostname,' +
        '  port: url.port || (url.protocol === "https:" ? 443 : 80),' +
        '  path: url.pathname,' +
        '  headers: {' +
        '    "Content-Type": "application/json",' +
        '    "Content-Length": Buffer.byteLength(postData)' +
        (_sgApiKey ? '    ,"Authorization": "Bearer ' + _sgApiKey.replace(/"/g, '\\"') + '"' : '') +
        '  }' +
        '};' +
        'var transport = url.protocol === "https:" ? https : http;' +
        'var req = transport.request(options, function(res) {' +
        '  var data = "";' +
        '  res.on("data", function(c) { data += c; });' +
        '  res.on("end", function() { process.stdout.write(data); });' +
        '});' +
        'req.on("error", function(e) { process.stdout.write(JSON.stringify({decision:"allow",reason:"server_error"})); });' +
        'req.write(postData);' +
        'req.end();';

      var result = _origChildProcess.spawnSync(process.execPath, ['-e', scriptCode], {
        timeout: 10000,
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe']
      });

      _sgInEvaluation = false;

      if (result.error || result.status !== 0) {
        var errMsg = result.error ? result.error.message : 'exit ' + result.status;
        if (_sgFailMode === 'closed') {
          // Fail-closed: deny on evaluation error.
          _sgAuditBuffer.add({
            action_type: actionType,
            action_name: actionName,
            decision: 'deny',
            reason: 'fail-closed',
            timestamp: new Date().toISOString()
          });
          throw new Error('SentinelGate: Action denied - server unreachable (fail-closed mode)');
        }
        // Fail-open: if evaluation cannot be performed, allow the action.
        process.stderr.write('[SentinelGate] Warning: Policy evaluation failed (fail-open): ' + errMsg + '\n');
        _sgAuditBuffer.add({
          action_type: actionType,
          action_name: actionName,
          decision: 'allow',
          reason: 'evaluation_error',
          timestamp: new Date().toISOString()
        });
        return { decision: 'allow', reason: 'evaluation_error' };
      }

      var stdout = (result.stdout || '').trim();
      if (!stdout) {
        if (_sgFailMode === 'closed') {
          throw new Error('SentinelGate: Action denied - server unreachable (fail-closed mode)');
        }
        process.stderr.write('[SentinelGate] Warning: Empty response from policy server (fail-open)\n');
        return { decision: 'allow', reason: 'empty_response' };
      }

      var resp = JSON.parse(stdout);

      // Handle server error responses (e.g., {"error":"CSRF token invalid"}).
      if (resp.error && !resp.decision) {
        if (_sgFailMode === 'closed') {
          throw new Error('SentinelGate: Action denied - server error: ' + resp.error + ' (fail-closed mode)');
        }
        process.stderr.write('[SentinelGate] Warning: Server error (fail-open): ' + resp.error + '\n');
        return { decision: 'allow', reason: 'server_error' };
      }

      // Record in audit buffer.
      _sgAuditBuffer.add({
        action_type: actionType,
        action_name: actionName,
        decision: resp.decision,
        request_id: resp.request_id,
        rule_id: resp.rule_id,
        timestamp: new Date().toISOString()
      });

      // Handle decision.
      if (resp.decision === 'allow') {
        var allowResult = { decision: 'allow' };
        _sgCache.set(cacheKey, allowResult);
        return allowResult;
      }

      if (resp.decision === 'deny') {
        return {
          decision: 'deny',
          reason: resp.reason || 'Policy denied',
          helpText: resp.help_text || '',
          helpUrl: resp.help_url || ''
        };
      }

      if (resp.decision === 'approval_required') {
        return _sgPollApprovalSync(resp.request_id, cacheKey);
      }

      // Unknown decision: fail-open.
      return { decision: 'allow', reason: 'unknown_decision' };

    } catch (e) {
      _sgInEvaluation = false;
      // Re-throw SentinelGate deny errors (from fail-closed paths).
      if (e.message && e.message.indexOf('SentinelGate:') === 0) {
        throw e;
      }
      if (_sgFailMode === 'closed') {
        throw new Error('SentinelGate: Action denied - server unreachable (fail-closed mode)');
      }
      // Fail-open on any error.
      process.stderr.write('[SentinelGate] Warning: Policy evaluation error (fail-open): ' + e.message + '\n');
      return { decision: 'allow', reason: 'evaluation_exception' };
    }
  }

  // ── Approval Polling ───────────────────────────────────────────────────────
  // Blocks until approval is granted, denied, or timeout (60s max).

  function _sgPollApprovalSync(requestId, cacheKey) {
    var maxPolls = 30;  // 30 x 2s = 60s timeout
    var pollInterval = 2; // seconds

    for (var i = 0; i < maxPolls; i++) {
      try {
        _sgInEvaluation = true;

        var scriptCode =
          'var http = require("http");' +
          'var https = require("https");' +
          'var url = new URL("' + _sgServerAddr.replace(/"/g, '\\"') +
          '/admin/api/v1/policy/evaluate/' + encodeURIComponent(requestId) + '/status");' +
          'var options = {' +
          '  method: "GET",' +
          '  hostname: url.hostname,' +
          '  port: url.port || (url.protocol === "https:" ? 443 : 80),' +
          '  path: url.pathname' +
          (_sgApiKey ? '  ,headers: {"Authorization": "Bearer ' + _sgApiKey.replace(/"/g, '\\"') + '"}' : '') +
          '};' +
          'var transport = url.protocol === "https:" ? https : http;' +
          'var req = transport.request(options, function(res) {' +
          '  var data = "";' +
          '  res.on("data", function(c) { data += c; });' +
          '  res.on("end", function() { process.stdout.write(data); });' +
          '});' +
          'req.on("error", function(e) { process.stdout.write(JSON.stringify({status:"error"})); });' +
          'req.end();';

        var result = _origChildProcess.spawnSync(process.execPath, ['-e', scriptCode], {
          timeout: 5000,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe']
        });

        _sgInEvaluation = false;

        if (!result.error && result.status === 0 && result.stdout) {
          var resp = JSON.parse(result.stdout.trim());

          if (resp.status === 'allow' || resp.decision === 'allow') {
            var allowResult = { decision: 'allow' };
            if (cacheKey) _sgCache.set(cacheKey, allowResult);
            return allowResult;
          }

          if (resp.status === 'deny' || resp.decision === 'deny') {
            return { decision: 'deny', reason: resp.reason || 'Approval denied' };
          }

          // Still pending: continue polling.
        }
      } catch (e) {
        _sgInEvaluation = false;
      }

      // Sleep between polls using Atomics.wait on a shared buffer.
      try {
        var sab = new SharedArrayBuffer(4);
        var ia = new Int32Array(sab);
        Atomics.wait(ia, 0, 0, pollInterval * 1000);
      } catch (e) {
        // Fallback: use spawnSync sleep.
        _origChildProcess.spawnSync('sleep', [String(pollInterval)]);
      }
    }

    // Timeout: deny by default.
    return { decision: 'deny', reason: 'Approval timeout after ' + (maxPolls * pollInterval) + 's' };
  }

  // ── Attempt periodic audit buffer flush ────────────────────────────────────
  var _sgFlushTimer = setInterval(function() {
    _sgAuditBuffer.flush();
  }, 30000);
  // Unref so it doesn't keep the process alive.
  if (_sgFlushTimer && typeof _sgFlushTimer.unref === 'function') {
    _sgFlushTimer.unref();
  }

  // ── child_process Interception ─────────────────────────────────────────────
  // Intercepts: exec, execSync, spawn, spawnSync, fork, execFile, execFileSync

  function _sgShouldSkipCommand(cmd, args) {
    // Skip interception during our own evaluation calls.
    if (_sgInEvaluation) return true;
    return false;
  }

  function _sgExtractCommand(cmd, cmdArgs) {
    var command = String(cmd || '');
    var argsList = [];
    if (Array.isArray(cmdArgs)) {
      argsList = cmdArgs.map(String);
    }
    return {
      command: command,
      args: argsList,
      full_command: command + (argsList.length > 0 ? ' ' + argsList.join(' ') : '')
    };
  }

  function _sgEvaluateCommand(cmd, cmdArgs) {
    var info = _sgExtractCommand(cmd, cmdArgs);
    return _sgEvaluateSync('command_exec', info.command, {
      args: info.args,
      full_command: info.full_command
    }, {
      command: info.command
    });
  }

  // exec(command[, options][, callback])
  _cp.exec = function _sgExec(command, options, callback) {
    if (_sgInEvaluation) return _origChildProcess.exec.apply(this, arguments);
    var result = _sgEvaluateCommand(command, []);
    if (result.decision === 'deny') {
      var err = new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
      if (typeof options === 'function') {
        options(err, '', '');
        return;
      }
      if (typeof callback === 'function') {
        callback(err, '', '');
        return;
      }
      throw err;
    }
    return _origChildProcess.exec.apply(this, arguments);
  };

  // execSync(command[, options])
  _cp.execSync = function _sgExecSync(command, options) {
    if (_sgInEvaluation) return _origChildProcess.execSync.apply(this, arguments);
    var result = _sgEvaluateCommand(command, []);
    if (result.decision === 'deny') {
      throw new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
    }
    return _origChildProcess.execSync.apply(this, arguments);
  };

  // spawn(command[, args][, options])
  _cp.spawn = function _sgSpawn(command, args, options) {
    if (_sgInEvaluation) return _origChildProcess.spawn.apply(this, arguments);
    var cmdArgs = Array.isArray(args) ? args : [];
    var result = _sgEvaluateCommand(command, cmdArgs);
    if (result.decision === 'deny') {
      throw new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
    }
    return _origChildProcess.spawn.apply(this, arguments);
  };

  // spawnSync(command[, args][, options])
  _cp.spawnSync = function _sgSpawnSync(command, args, options) {
    if (_sgInEvaluation) return _origChildProcess.spawnSync.apply(this, arguments);
    var cmdArgs = Array.isArray(args) ? args : [];
    var result = _sgEvaluateCommand(command, cmdArgs);
    if (result.decision === 'deny') {
      throw new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
    }
    return _origChildProcess.spawnSync.apply(this, arguments);
  };

  // fork(modulePath[, args][, options])
  _cp.fork = function _sgFork(modulePath, args, options) {
    if (_sgInEvaluation) return _origChildProcess.fork.apply(this, arguments);
    var cmdArgs = Array.isArray(args) ? args : [];
    var result = _sgEvaluateCommand(modulePath, cmdArgs);
    if (result.decision === 'deny') {
      throw new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
    }
    return _origChildProcess.fork.apply(this, arguments);
  };

  // execFile(file[, args][, options][, callback])
  _cp.execFile = function _sgExecFile(file, args, options, callback) {
    if (_sgInEvaluation) return _origChildProcess.execFile.apply(this, arguments);
    var cmdArgs = Array.isArray(args) ? args : [];
    var result = _sgEvaluateCommand(file, cmdArgs);
    if (result.decision === 'deny') {
      var err = new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
      // Find the callback (could be args[1], args[2], or args[3]).
      var cb = typeof args === 'function' ? args :
               typeof options === 'function' ? options :
               typeof callback === 'function' ? callback : null;
      if (cb) {
        cb(err, '', '');
        return;
      }
      throw err;
    }
    return _origChildProcess.execFile.apply(this, arguments);
  };

  // execFileSync(file[, args][, options])
  _cp.execFileSync = function _sgExecFileSync(file, args, options) {
    if (_sgInEvaluation) return _origChildProcess.execFileSync.apply(this, arguments);
    var cmdArgs = Array.isArray(args) ? args : [];
    var result = _sgEvaluateCommand(file, cmdArgs);
    if (result.decision === 'deny') {
      throw new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
    }
    return _origChildProcess.execFileSync.apply(this, arguments);
  };

  // ── fs Interception ────────────────────────────────────────────────────────
  // Intercepts: readFile, readFileSync, writeFile, writeFileSync,
  //   appendFile, appendFileSync, unlink, unlinkSync,
  //   mkdir, mkdirSync, rmdir, rmdirSync, rm, rmSync

  var _fs = require('fs');
  var _origFs = {
    readFile: _fs.readFile,
    readFileSync: _fs.readFileSync,
    writeFile: _fs.writeFile,
    writeFileSync: _fs.writeFileSync,
    appendFile: _fs.appendFile,
    appendFileSync: _fs.appendFileSync,
    unlink: _fs.unlink,
    unlinkSync: _fs.unlinkSync,
    mkdir: _fs.mkdir,
    mkdirSync: _fs.mkdirSync,
    rmdir: _fs.rmdir,
    rmdirSync: _fs.rmdirSync,
    rm: _fs.rm,
    rmSync: _fs.rmSync
  };

  // ── Module Loader Guard ──────────────────────────────────────────────────
  // Node.js Module._extensions['.js'] uses fs.readFileSync to load module source.
  // With our fs patches, a deny-all policy would block require() from reading
  // .js files — breaking even basic module loading. We replace the extension
  // handlers to call the ORIGINAL (unpatched) readFileSync for the source read,
  // then call module._compile() as usual. User code executed inside _compile
  // still goes through our patched fs, so policy evaluation works correctly.
  var _Module = require('module');
  var _origExtJs = _Module._extensions['.js'];
  _Module._extensions['.js'] = function _sgExtJs(module, filename) {
    var content = _origFs.readFileSync(filename, 'utf8');
    // Strip BOM (same as Node.js internals).
    if (content.charCodeAt(0) === 0xFEFF) {
      content = content.slice(1);
    }
    module._compile(content, filename);
  };

  var _origExtJson = _Module._extensions['.json'];
  _Module._extensions['.json'] = function _sgExtJson(module, filename) {
    var content = _origFs.readFileSync(filename, 'utf8');
    try {
      module.exports = JSON.parse(content);
    } catch (err) {
      err.message = filename + ': ' + err.message;
      throw err;
    }
  };

  // Paths that should be skipped (no policy evaluation needed).
  function _sgShouldSkipPath(filePath) {
    if (typeof filePath !== 'string') return true;
    // Skip node_modules, bootstrap dir, /dev/, /proc/, /sys/, .lock files.
    if (filePath.indexOf('node_modules') !== -1) return true;
    if (filePath.indexOf('/dev/') === 0) return true;
    if (filePath.indexOf('/proc/') === 0) return true;
    if (filePath.indexOf('/sys/') === 0) return true;
    if (filePath.endsWith('.lock')) return true;
    // Skip the bootstrap directory itself (sentinelgate-bootstrap-*).
    if (filePath.indexOf('sentinelgate-bootstrap-') !== -1) return true;
    return false;
  }

  function _sgMakeFsWrapper(origFn, operation, isSync) {
    return function _sgFsWrapper() {
      if (_sgInEvaluation) return origFn.apply(_fs, arguments);

      var filePath = arguments[0];
      // Handle Buffer/URL file descriptors.
      if (typeof filePath === 'number' || (filePath && typeof filePath === 'object' && filePath instanceof URL)) {
        return origFn.apply(_fs, arguments);
      }
      var pathStr = String(filePath);

      if (_sgShouldSkipPath(pathStr)) {
        return origFn.apply(_fs, arguments);
      }

      // Determine mode from operation name.
      var mode = 'read';
      if (operation.indexOf('write') !== -1 || operation.indexOf('append') !== -1) {
        mode = 'write';
      } else if (operation.indexOf('unlink') !== -1 || operation.indexOf('rm') !== -1) {
        mode = 'delete';
      } else if (operation.indexOf('mkdir') !== -1) {
        mode = 'create';
      }

      var result = _sgEvaluateSync('file_access', operation, {
        path: pathStr,
        file_path: pathStr,
        mode: mode
      }, {
        path: pathStr
      });

      if (result.decision === 'deny') {
        var err = new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
        err.code = 'EACCES';

        if (!isSync) {
          // For async versions, find the callback and call it with error.
          var args = Array.prototype.slice.call(arguments);
          var cb = args[args.length - 1];
          if (typeof cb === 'function') {
            cb(err);
            return;
          }
        }
        throw err;
      }

      return origFn.apply(_fs, arguments);
    };
  }

  // Sync fs operations.
  _fs.readFileSync = _sgMakeFsWrapper(_origFs.readFileSync, 'readFileSync', true);
  _fs.writeFileSync = _sgMakeFsWrapper(_origFs.writeFileSync, 'writeFileSync', true);
  _fs.appendFileSync = _sgMakeFsWrapper(_origFs.appendFileSync, 'appendFileSync', true);
  _fs.unlinkSync = _sgMakeFsWrapper(_origFs.unlinkSync, 'unlinkSync', true);
  _fs.mkdirSync = _sgMakeFsWrapper(_origFs.mkdirSync, 'mkdirSync', true);
  _fs.rmdirSync = _sgMakeFsWrapper(_origFs.rmdirSync, 'rmdirSync', true);
  if (_origFs.rmSync) {
    _fs.rmSync = _sgMakeFsWrapper(_origFs.rmSync, 'rmSync', true);
  }

  // Async fs operations.
  _fs.readFile = _sgMakeFsWrapper(_origFs.readFile, 'readFile', false);
  _fs.writeFile = _sgMakeFsWrapper(_origFs.writeFile, 'writeFile', false);
  _fs.appendFile = _sgMakeFsWrapper(_origFs.appendFile, 'appendFile', false);
  _fs.unlink = _sgMakeFsWrapper(_origFs.unlink, 'unlink', false);
  _fs.mkdir = _sgMakeFsWrapper(_origFs.mkdir, 'mkdir', false);
  _fs.rmdir = _sgMakeFsWrapper(_origFs.rmdir, 'rmdir', false);
  if (_origFs.rm) {
    _fs.rm = _sgMakeFsWrapper(_origFs.rm, 'rm', false);
  }

  // ── fs.promises Interception ────────────────────────────────────────────────
  // Modern Node.js apps (ESM) often use fs.promises.readFile etc.
  // fs.promises shares the same underlying implementation, but we need to
  // wrap each method to add policy evaluation.

  if (_fs.promises) {
    var _origFsPromises = {
      readFile: _fs.promises.readFile,
      writeFile: _fs.promises.writeFile,
      appendFile: _fs.promises.appendFile,
      unlink: _fs.promises.unlink,
      mkdir: _fs.promises.mkdir,
      rmdir: _fs.promises.rmdir,
      rm: _fs.promises.rm
    };

    function _sgMakePromiseWrapper(origFn, operation) {
      return function _sgFsPromiseWrapper() {
        if (_sgInEvaluation) return origFn.apply(_fs.promises, arguments);

        var filePath = arguments[0];
        if (typeof filePath === 'number' || (filePath && typeof filePath === 'object' && filePath instanceof URL)) {
          return origFn.apply(_fs.promises, arguments);
        }
        var pathStr = String(filePath);

        if (_sgShouldSkipPath(pathStr)) {
          return origFn.apply(_fs.promises, arguments);
        }

        var mode = 'read';
        if (operation.indexOf('write') !== -1 || operation.indexOf('append') !== -1) {
          mode = 'write';
        } else if (operation.indexOf('unlink') !== -1 || operation.indexOf('rm') !== -1) {
          mode = 'delete';
        } else if (operation.indexOf('mkdir') !== -1) {
          mode = 'create';
        }

        var result = _sgEvaluateSync('file_access', operation, {
          path: pathStr,
          file_path: pathStr,
          mode: mode
        }, {
          path: pathStr
        });

        if (result.decision === 'deny') {
          var err = new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
          err.code = 'EACCES';
          return Promise.reject(err);
        }

        return origFn.apply(_fs.promises, arguments);
      };
    }

    _fs.promises.readFile = _sgMakePromiseWrapper(_origFsPromises.readFile, 'readFile');
    _fs.promises.writeFile = _sgMakePromiseWrapper(_origFsPromises.writeFile, 'writeFile');
    _fs.promises.appendFile = _sgMakePromiseWrapper(_origFsPromises.appendFile, 'appendFile');
    _fs.promises.unlink = _sgMakePromiseWrapper(_origFsPromises.unlink, 'unlink');
    _fs.promises.mkdir = _sgMakePromiseWrapper(_origFsPromises.mkdir, 'mkdir');
    _fs.promises.rmdir = _sgMakePromiseWrapper(_origFsPromises.rmdir, 'rmdir');
    if (_origFsPromises.rm) {
      _fs.promises.rm = _sgMakePromiseWrapper(_origFsPromises.rm, 'rm');
    }
  }

  // ── fetch Interception (Node.js 18+) ──────────────────────────────────────

  if (typeof globalThis.fetch === 'function') {
    var _origFetch = globalThis.fetch;
    globalThis.fetch = function _sgFetch(input, init) {
      if (_sgInEvaluation) return _origFetch.call(globalThis, input, init);

      var url;
      if (typeof input === 'string') {
        url = input;
      } else if (input && typeof input === 'object' && input.url) {
        url = input.url;
      } else if (input instanceof URL) {
        url = input.toString();
      } else {
        // Cannot determine URL; pass through.
        return _origFetch.call(globalThis, input, init);
      }

      try {
        var parsed = new URL(url);
        // Skip evaluation for requests to SentinelGate server itself.
        var serverUrl = new URL(_sgServerAddr);
        if (parsed.hostname === serverUrl.hostname && parsed.port === serverUrl.port) {
          return _origFetch.call(globalThis, input, init);
        }

        var method = (init && init.method) ? init.method.toUpperCase() : 'GET';
        var headers = {};
        if (init && init.headers) {
          if (typeof init.headers.entries === 'function') {
            var iter = init.headers.entries();
            var entry;
            while (!(entry = iter.next()).done) {
              headers[entry.value[0]] = entry.value[1];
            }
          } else if (typeof init.headers === 'object') {
            headers = Object.assign({}, init.headers);
          }
        }

        var result = _sgEvaluateSync('http_request', method, {
          url: url,
          headers: headers
        }, {
          url: url,
          domain: parsed.hostname,
          port: parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80),
          scheme: parsed.protocol.replace(':', ''),
          path: parsed.pathname
        });

        if (result.decision === 'deny') {
          return Promise.reject(new Error('SentinelGate: Action denied - ' + (result.reason || 'policy')));
        }
      } catch (e) {
        // URL parsing error or evaluation error: pass through (fail-open).
        if (e.message && e.message.indexOf('SentinelGate:') === 0) {
          return Promise.reject(e);
        }
      }

      return _origFetch.call(globalThis, input, init);
    };
  }

  // ── http/https.request Interception ────────────────────────────────────────

  function _sgMakeHttpWrapper(origRequest, transport, defaultScheme) {
    return function _sgHttpRequest(options, callback) {
      if (_sgInEvaluation) return origRequest.call(transport, options, callback);

      try {
        var hostname, port, path, method, scheme;

        if (typeof options === 'string') {
          var parsed = new URL(options);
          hostname = parsed.hostname;
          port = parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80);
          path = parsed.pathname + parsed.search;
          method = 'GET';
          scheme = parsed.protocol.replace(':', '');
        } else if (options instanceof URL) {
          hostname = options.hostname;
          port = parseInt(options.port) || (options.protocol === 'https:' ? 443 : 80);
          path = options.pathname + options.search;
          method = 'GET';
          scheme = options.protocol.replace(':', '');
        } else if (options && typeof options === 'object') {
          hostname = options.hostname || options.host || 'localhost';
          // Strip port from host if present.
          if (hostname.indexOf(':') !== -1) {
            var parts = hostname.split(':');
            hostname = parts[0];
            port = parseInt(parts[1]) || undefined;
          }
          port = port || options.port || (defaultScheme === 'https' ? 443 : 80);
          path = options.path || '/';
          method = (options.method || 'GET').toUpperCase();
          scheme = defaultScheme;
        } else {
          return origRequest.call(transport, options, callback);
        }

        // Skip evaluation for requests to SentinelGate server itself.
        try {
          var serverUrl = new URL(_sgServerAddr);
          if (hostname === serverUrl.hostname && String(port) === (serverUrl.port || (serverUrl.protocol === 'https:' ? '443' : '80'))) {
            return origRequest.call(transport, options, callback);
          }
        } catch (e) {
          // Ignore URL parse errors on server addr.
        }

        var url = scheme + '://' + hostname + ':' + port + path;
        var result = _sgEvaluateSync('http_request', method, {
          url: url,
          hostname: hostname,
          port: port,
          path: path
        }, {
          url: url,
          domain: hostname,
          port: port,
          scheme: scheme,
          path: path
        });

        if (result.decision === 'deny') {
          throw new Error('SentinelGate: Action denied - ' + (result.reason || 'policy'));
        }
      } catch (e) {
        if (e.message && e.message.indexOf('SentinelGate:') === 0) {
          throw e;
        }
        // Fail-open on evaluation errors.
      }

      return origRequest.call(transport, options, callback);
    };
  }

  _origHttp.request = _sgMakeHttpWrapper(_origHttpRequest, _origHttp, 'http');
  _origHttps.request = _sgMakeHttpWrapper(_origHttpsRequest, _origHttps, 'https');

  // Flush audit buffer on process exit.
  process.on('exit', function() {
    _sgAuditBuffer.flush();
  });

})();
