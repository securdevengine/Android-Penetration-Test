"""Shared exception types for the safety/control layer.

Every failure a safety control raises is a subclass of :class:`SafetyError`,
so callers can catch the whole family with a single ``except`` while still
being able to distinguish specific refusal reasons for audit logging.
"""


class SafetyError(Exception):
    """Base class for every safety-control refusal or misconfiguration."""


class AuthorizationError(SafetyError):
    """Rules-of-Engagement missing, malformed, or with an invalid signature."""


class ScopeError(SafetyError):
    """Requested target (host/URL/package) is not inside the authorized scope."""


class WindowError(SafetyError):
    """The current time is outside the authorized testing window."""


class KillSwitchEngaged(SafetyError):
    """An operator kill-switch is active; all active testing must stop now."""


class BudgetExceeded(SafetyError):
    """A configured request/concurrency budget has been exhausted."""


class ApprovalRequired(SafetyError):
    """An intrusive test was invoked without the required engagement approval."""
