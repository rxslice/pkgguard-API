"""
Policy gateway for autonomous coding agents.

The gateway turns an agent-generated shell command into an explicit
ALLOW/REVIEW/BLOCK decision before the command reaches a package manager.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .parsing import parse_install_command
from .scoring import Assessment
from .service import verify_many
from .scoring import NEW_PACKAGE_POLICIES

_SHELL_CONTROL = (";", "|", "&", "\n", "\r", "`", "$(", "${", "<", ">")
_PACKAGE_MANAGER = re.compile(r"^(?:npm|yarn|pnpm|bun|pip3?|uv|poetry|cargo)\s+", re.I)


@dataclass
class CommandDecision:
    command: str
    decision: str
    ecosystem: Optional[str]
    packages: List[str] = field(default_factory=list)
    assessments: List[Assessment] = field(default_factory=list)
    reason: str = ""

    @property
    def safe_to_execute(self) -> bool:
        return self.decision == "ALLOW"

    def to_dict(self, *, allow_review: bool = False) -> dict:
        safe = self.safe_to_execute or (
            allow_review
            and self.decision == "REVIEW"
            and self.ecosystem is not None
            and bool(self.packages)
        )
        return {
            "command": self.command,
            "decision": self.decision,
            "ecosystem": self.ecosystem,
            "packages": self.packages,
            "assessments": [result.__dict__ for result in self.assessments],
            "reason": self.reason,
            "safe_to_execute": safe,
        }


def decision_to_dict(decision: object, *, allow_review: bool = False) -> dict:
    if hasattr(decision, "to_dict"):
        return decision.to_dict(allow_review=allow_review)
    safe = getattr(decision, "safe_to_execute", False) or (
        allow_review
        and getattr(decision, "decision", None) == "REVIEW"
        and getattr(decision, "ecosystem", None) is not None
        and bool(getattr(decision, "packages", []))
    )
    return {
        "command": getattr(decision, "command", ""),
        "decision": getattr(decision, "decision", "REVIEW"),
        "ecosystem": getattr(decision, "ecosystem", None),
        "packages": list(getattr(decision, "packages", [])),
        "assessments": [result.__dict__ for result in getattr(decision, "assessments", [])],
        "reason": getattr(decision, "reason", ""),
        "safe_to_execute": safe,
    }


def authorize_command(
    command: str,
    new_package_policy: str = "block",
) -> CommandDecision:
    """Authorize an agent command without executing it.

    Unknown commands are denied rather than treated as safe: this first MVP is
    intentionally limited to package-manager install commands.
    """
    if new_package_policy not in NEW_PACKAGE_POLICIES:
        raise ValueError(
            f"Unsupported new package policy '{new_package_policy}'. "
            f"Supported: {list(NEW_PACKAGE_POLICIES)}"
        )

    if (
        not command.strip()
        or not _PACKAGE_MANAGER.match(command.strip())
        or any(marker in command for marker in _SHELL_CONTROL)
    ):
        return CommandDecision(
            command=command,
            decision="REVIEW",
            ecosystem=None,
            reason="Compound or shell-interpolated commands require human review.",
        )

    ecosystem, packages = parse_install_command(command)
    if not ecosystem or not packages:
        return CommandDecision(
            command=command,
            decision="REVIEW",
            ecosystem=ecosystem,
            packages=packages,
            reason="No supported package-install command was recognized; require human review.",
        )

    assessments = verify_many(packages, ecosystem, new_package_policy)
    if any(result.verdict == "BLOCK" for result in assessments):
        decision = "BLOCK"
        reason = "At least one package was blocked by pkgguard."
    elif any(result.verdict == "REVIEW" for result in assessments):
        decision = "REVIEW"
        reason = "At least one package requires human review."
    else:
        decision = "ALLOW"
        reason = "All packages passed the configured pre-install checks."

    return CommandDecision(
        command=command,
        decision=decision,
        ecosystem=ecosystem,
        packages=packages,
        assessments=assessments,
        reason=reason,
    )
