"""
pkgguard — built by Blvkware (https://blvkware.dev)
Licensed under the Apache License 2.0. See LICENSE.
pkgguard CLI.

Two modes, both designed to sit in front of a package manager:

    # check names directly
    pkgguard check --ecosystem npm react-codeshift express

    # parse an install command an agent is about to run
    echo "npm install react-codeshift lodash" | pkgguard scan-command

    # scan a manifest in CI
    pkgguard scan-manifest package.json
    pkgguard scan-manifest requirements.txt

Exit codes:
    0 - command passed its configured gate
    1 - a scan found BLOCK, or authorize returned REVIEW/BLOCK
    2 - usage error
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from .agent import authorize_command, decision_to_dict
from .parsing import parse_install_command
from .registries import SUPPORTED_ECOSYSTEMS
from .scoring import NEW_PACKAGE_POLICIES
from .sarif import to_sarif
from .service import verify_many

RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BOLD = "\033[1m"
RESET = "\033[0m"

_COLORS = {"BLOCK": RED, "REVIEW": YELLOW, "ALLOW": GREEN}


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if _supports_color() else text


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

def parse_manifest(path: Path) -> Tuple[Optional[str], List[str]]:
    name = path.name.lower()

    if name == "package.json":
        data = json.loads(path.read_text(encoding="utf-8"))
        deps = {}
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps.update(data.get(key, {}) or {})
        return "npm", sorted(deps.keys())

    if name in ("requirements.txt", "requirements-dev.txt") or name.endswith(".requirements.txt"):
        names = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            pkg = re.split(r"[><=~!\[;]+", line)[0].strip()
            if pkg:
                names.append(pkg)
        return "pypi", names

    if name == "cargo.toml":
        names = []
        in_deps = False
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("["):
                in_deps = "dependencies" in s
                continue
            if in_deps and "=" in s:
                names.append(s.split("=")[0].strip().strip('"'))
        return "crates", names

    return None, []


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def render(results, as_json: bool, as_sarif: bool = False, *, fail_on_review: bool = False,
           path: Optional[str] = None) -> int:
    if as_sarif:
        print(json.dumps(to_sarif(results, path=path), indent=2))
        return 1 if any(r.verdict == "BLOCK" or (fail_on_review and r.verdict == "REVIEW") for r in results) else 0
    if as_json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        for r in results:
            color = _COLORS.get(r.verdict, "")
            header = f"{_c(r.verdict.ljust(6), color)} {_c(r.name, BOLD)}  [{r.ecosystem}]  risk={r.risk_score}"
            print(header)
            for s in r.signals:
                print(f"       - {s}")
            if r.verdict != "ALLOW" and r.recommendation:
                print(f"       > {r.recommendation}")
            print()

    blocked = sum(1 for r in results if r.verdict == "BLOCK")
    if not as_json:
        total = len(results)
        print(f"{total} checked | {blocked} blocked | "
              f"{sum(1 for r in results if r.verdict == 'REVIEW')} review | "
              f"{sum(1 for r in results if r.verdict == 'ALLOW')} allowed")
    return 1 if blocked or (fail_on_review and any(r.verdict == "REVIEW" for r in results)) else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pkgguard",
        description="Verify package names before installing them. Catches LLM-hallucinated "
                    "and slopsquatted dependencies.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output.")
    parser.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0 for code-scanning tools.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Check package names directly.")
    p_check.add_argument("names", nargs="+")
    p_check.add_argument("--ecosystem", "-e", default="npm", choices=list(SUPPORTED_ECOSYSTEMS))
    p_check.add_argument("--new-package-policy", choices=NEW_PACKAGE_POLICIES, default="block")

    p_cmd = sub.add_parser("scan-command", help="Parse an install command from an argument or stdin.")
    p_cmd.add_argument("command_text", nargs="?", help="If omitted, reads from stdin.")
    p_cmd.add_argument("--new-package-policy", choices=NEW_PACKAGE_POLICIES, default="block")

    p_auth = sub.add_parser("authorize", help="Authorize an agent-generated install command.")
    p_auth.add_argument("command_text", nargs="?", help="If omitted, reads from stdin.")
    p_auth.add_argument(
        "--allow-review",
        action="store_true",
        help="Permit REVIEW decisions; BLOCK and unknown commands still fail.",
    )
    p_auth.add_argument(
        "--new-package-policy",
        choices=NEW_PACKAGE_POLICIES,
        default="block",
        help="Treat very new existing packages as BLOCK or REVIEW.",
    )

    p_man = sub.add_parser("scan-manifest", help="Scan package.json / requirements.txt / Cargo.toml.")
    p_man.add_argument("path")
    p_man.add_argument(
        "--allow-review",
        action="store_true",
        help="Do not fail when a package is REVIEWed; BLOCK findings still fail.",
    )
    p_man.add_argument("--new-package-policy", choices=NEW_PACKAGE_POLICIES, default="block")

    args = parser.parse_args(argv)

    if args.command == "check":
        results = verify_many(args.names, args.ecosystem, args.new_package_policy)
        return render(results, args.json, args.sarif)

    if args.command == "scan-command":
        cmd = args.command_text
        if not cmd:
            cmd = sys.stdin.read()
        eco, names = parse_install_command(cmd)
        if not eco or not names:
            if not args.json:
                print("No install command recognized — nothing to check.")
            return 0
        results = verify_many(names, eco, args.new_package_policy)
        return render(results, args.json, args.sarif)

    if args.command == "authorize":
        command = args.command_text
        if not command:
            command = sys.stdin.read()
        decision = authorize_command(command, args.new_package_policy)
        payload = decision_to_dict(decision, allow_review=args.allow_review)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"{decision.decision}: {decision.reason}")
            if decision.packages:
                print(f"Packages: {', '.join(decision.packages)}")
            for result in decision.assessments:
                print(f"  {result.verdict}: {result.name} (risk={result.risk_score})")
        if payload["safe_to_execute"]:
            return 0
        return 1

    if args.command == "scan-manifest":
        path = Path(args.path)
        if not path.exists():
            print(f"No such file: {path}", file=sys.stderr)
            return 2
        eco, names = parse_manifest(path)
        if not eco:
            print(f"Unrecognized manifest type: {path.name}", file=sys.stderr)
            return 2
        if not names:
            if not args.json:
                print("No dependencies found.")
            return 0
        results = verify_many(names, eco, args.new_package_policy)
        return render(
            results,
            args.json,
            args.sarif,
            fail_on_review=not args.allow_review,
            path=str(path),
        )

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
