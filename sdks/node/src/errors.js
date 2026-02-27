'use strict';

/**
 * Base error class for SentinelGate SDK errors.
 */
class SentinelGateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SentinelGateError';
  }
}

/**
 * Raised when a policy evaluation results in a deny decision.
 */
class PolicyDeniedError extends SentinelGateError {
  constructor(message, { ruleId = '', ruleName = '', reason = '', helpUrl = '', helpText = '' } = {}) {
    super(message || 'Policy denied');
    this.name = 'PolicyDeniedError';
    this.ruleId = ruleId;
    this.ruleName = ruleName;
    this.reason = reason;
    this.helpUrl = helpUrl;
    this.helpText = helpText;
  }
}

/**
 * Raised when an approval request times out.
 */
class ApprovalTimeoutError extends SentinelGateError {
  constructor(message, { requestId = '' } = {}) {
    super(message || 'Approval request timed out');
    this.name = 'ApprovalTimeoutError';
    this.requestId = requestId;
  }
}

/**
 * Raised when the SentinelGate server is unreachable (fail-closed mode).
 */
class ServerUnreachableError extends SentinelGateError {
  constructor(message) {
    super(message || 'SentinelGate server unreachable');
    this.name = 'ServerUnreachableError';
  }
}

module.exports = {
  SentinelGateError,
  PolicyDeniedError,
  ApprovalTimeoutError,
  ServerUnreachableError,
};
