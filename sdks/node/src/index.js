'use strict';

const SentinelGateClient = require('./client');
const {
  SentinelGateError,
  PolicyDeniedError,
  ApprovalTimeoutError,
  ServerUnreachableError,
} = require('./errors');

module.exports = {
  SentinelGateClient,
  SentinelGateError,
  PolicyDeniedError,
  ApprovalTimeoutError,
  ServerUnreachableError,
  default: SentinelGateClient,
};
