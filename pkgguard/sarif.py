"""SARIF output for CI and code-scanning integrations."""
from __future__ import annotations

from typing import Iterable, Optional


def _level(verdict: str) -> str:
    return {"BLOCK": "error", "REVIEW": "warning"}.get(verdict, "note")


def to_sarif(results: Iterable[object], *, path: Optional[str] = None) -> dict:
    """Convert package assessments into a SARIF 2.1.0 document."""
    rules = {}
    findings = []
    for result in results:
        verdict = getattr(result, "verdict", "REVIEW")
        name = getattr(result, "name", "unknown")
        ecosystem = getattr(result, "ecosystem", "unknown")
        rule_id = f"pkgguard/{verdict.lower()}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": f"pkgguard {verdict.lower()}",
                "shortDescription": {"text": f"Package requires {verdict.lower()}"},
                "helpUri": "https://github.com/rxslice/pkgguard-API",
            },
        )
        message = getattr(result, "recommendation", None) or "; ".join(
            getattr(result, "signals", []) or []
        ) or f"{name} requires {verdict.lower()}."
        finding = {
            "ruleId": rule_id,
            "level": _level(verdict),
            "message": {"text": f"{ecosystem} package '{name}': {message}"},
            "properties": {
                "package": name,
                "ecosystem": ecosystem,
                "verdict": verdict,
                "riskScore": getattr(result, "risk_score", 0),
            },
        }
        if path:
            finding["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": path}}}
            ]
        findings.append(finding)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pkgguard",
                        "informationUri": "https://github.com/rxslice/pkgguard-API",
                        "rules": list(rules.values()),
                    }
                },
                "results": findings,
            }
        ],
    }
