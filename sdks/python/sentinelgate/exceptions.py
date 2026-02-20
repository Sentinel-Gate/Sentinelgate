"""SentinelGate SDK exceptions."""


class SentinelGateError(Exception):
    """Base exception for SentinelGate SDK errors."""
    pass


class PolicyDeniedError(SentinelGateError):
    """Raised when a policy evaluation results in a deny decision."""

    def __init__(self, message="Policy denied", rule_id="", rule_name="",
                 reason="", help_url="", help_text=""):
        super().__init__(message)
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.reason = reason
        self.help_url = help_url
        self.help_text = help_text


class ApprovalTimeoutError(SentinelGateError):
    """Raised when an approval request times out."""

    def __init__(self, message="Approval request timed out", request_id=""):
        super().__init__(message)
        self.request_id = request_id


class ServerUnreachableError(SentinelGateError):
    """Raised when the SentinelGate server is unreachable (fail-closed mode)."""
    pass
