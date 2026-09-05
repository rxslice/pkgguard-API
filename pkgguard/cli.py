"""
pkgguard — built by Blvkware (https://blvkware.dev)
Licensed under the Business Source License 1.1. See LICENSE.
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
    0 - nothing blocked
    1 - at least one BLOCK verdict (fail the build / stop the agent)
    2 - usage error
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from .registries import SUPPORTED_ECOSYSTEMS
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
# Install-command parsing
# ---------------------------------------------------------------------------

_INSTALL_PATTERNS = [
    (re.compile(r"\bnpm\s+(?:i|install|add)\s+(.+)", re.I), "npm"),
    (re.compile(r"\b(?:yarn|pnpm|bun)\s+add\s+(.+)", re.I), "npm"),
    (re.compile(r"\bpip3?\s+install\s+(.+)", re.I), "pypi"),
    (re.compile(r"\buv\s+(?:pip\s+)?(?:install|add)\s+(.+)", re.I), "pypi"),
    (re.compile(r"\bpoetry\s+add\s+(.+)", re.I), "pypi"),
    (re.compile(r"\bcargo\s+add\s+(.+)", re.I), "crates"),
]

_FLAG = re.compile(r"^-")


def parse_install_command(cmd: str) -> Tuple[Optional[str], List[str]]:
    """Extract (ecosystem, package_names) from a shell install command."""
    for pattern, eco in _INSTALL_PATTERNS:
        m = pattern.search(cmd)
        if not m:
            continue
        raw = m.group(1)
        names: List[str] = []
        for tok in raw.split():
            tok = tok.strip().strip("\"'")
            if not tok or _FLAG.match(tok):
                continue
            # Strip version specifiers: pkg==1.2, pkg@1.2, pkg>=1
            tok = re.split(r"[><=~!]+", tok)[0]
            if tok.startswith("@"):           # scoped npm package: @scope/name@1.2
                parts = tok.split("@")
                tok = "@" + parts[1] if len(parts) > 1 else tok
            else:
                tok = tok.split("@")[0]
            tok = tok.strip()
            # Skip local paths, URLs, and git refs — not registry lookups.
            if not tok or "/" in tok and not tok.startswith("@"):
                continue
            if tok.startswith(".") or "://" in tok:
                continue
            names.append(tok)
        return eco, names
    return None, []


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

def render(results, as_json: bool) -> int:
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
    return 1 if blocked else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pkgguard",
        description="Verify package names before installing them. Catches LLM-hallucinated "
                    "and slopsquatted dependencies.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Check package names directly.")
    p_check.add_argument("names", nargs="+")
    p_check.add_argument("--ecosystem", "-e", default="npm", choices=list(SUPPORTED_ECOSYSTEMS))

    p_cmd = sub.add_parser("scan-command", help="Parse an install command from an argument or stdin.")
    p_cmd.add_argument("command", nargs="?", help="If omitted, reads from stdin.")

    p_man = sub.add_parser("scan-manifest", help="Scan package.json / requirements.txt / Cargo.toml.")
    p_man.add_argument("path")

    args = parser.parse_args(argv)

    if args.command == "check":
        results = verify_many(args.names, args.ecosystem)
        return render(results, args.json)

    if args.command == "scan-command":
        cmd = args.command_text if hasattr(args, "command_text") else args.command
        if not cmd:
            cmd = sys.stdin.read()
        eco, names = parse_install_command(cmd)
        if not eco or not names:
            if not args.json:
                print("No install command recognized — nothing to check.")
            return 0
        results = verify_many(names, eco)
        return render(results, args.json)

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
        results = verify_many(names, eco)
        return render(results, args.json)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
