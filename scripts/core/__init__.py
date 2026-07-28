"""
Enterprise safety and control layer for the Android Penetration Test toolkit.

This package provides the authorization, scope-enforcement, evidence-protection,
audit, and safe-traffic controls that every active testing tool must route
through before it is allowed to touch a target.

Design principle: **fail closed**. If a required control cannot be satisfied
(no signed rules-of-engagement, target out of scope, testing window closed,
kill-switch engaged), the operation is refused rather than silently permitted.

Modules
-------
roe        Rules-of-Engagement: signed authorization, scope, window, kill-switch.
evidence   Redaction, encrypted evidence storage, tamper-evident audit log.
netcontrol Safe HTTP session: TLS-on-by-default, request budget, rate limiting.
errors     Shared exception types.
"""

from .errors import (
    SafetyError,
    AuthorizationError,
    ScopeError,
    WindowError,
    KillSwitchEngaged,
    BudgetExceeded,
    ApprovalRequired,
)

__all__ = [
    "SafetyError",
    "AuthorizationError",
    "ScopeError",
    "WindowError",
    "KillSwitchEngaged",
    "BudgetExceeded",
    "ApprovalRequired",
]

__version__ = "0.1.0"
