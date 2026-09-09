"""Pre-execution gate for package-manager commands.

This is the most direct agent integration: a wrapper that authorizes an
install command and only runs it if it passes the pkgguard policy. It is a
lightweight "pre-tool-use" pattern for autonomous shells and CI runners.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from typing import Sequence

from .agent import authorize_command


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off", ""}:
        return False
    return default


def _env_policy(default: str = "block") -> str:
    value = os.environ.get("PKGGUARD_NEW_PACKAGE_POLICY", "").strip().lower()
    if value in {"block", "review"}:
        return value
    return default


def _is_install_command(program: str, argv: Sequence[str]) -> bool:
    program_name = (program or "").lower()
    if not argv:
        return False
    first = str(argv[0]).lower()
    if program_name in {"npm", "yarn", "pnpm", "bun"}:
        return first in {"install", "i", "add"}
    if program_name in {"pip", "pip3"}:
        return first == "install"
    if program_name == "uv":
        return first in {"install", "add", "pip"} and (len(argv) == 1 or argv[1].lower() == "install")
    if program_name == "poetry":
        return first == "add"
    if program_name == "cargo":
        return first == "add"
    return False


def _command_to_string(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in argv)


def run_guarded(argv: Sequence[str], *, allow_review: bool | None = None, new_package_policy: str | None = None) -> int:
    """Execute a package-manager command only when pkgguard authorizes it."""
    if not argv:
        raise ValueError("No command provided.")
    allow_review = _env_bool("PKGGUARD_ALLOW_REVIEW", False) if allow_review is None else allow_review
    new_package_policy = _env_policy("block") if new_package_policy is None else new_package_policy
    command_text = _command_to_string(argv)
    decision = authorize_command(command_text, new_package_policy)
    payload = decision.to_dict(allow_review=allow_review)

    if not payload["safe_to_execute"]:
        print(f"{decision.decision}: {decision.reason}", file=sys.stderr)
        if decision.packages:
            print(f"Packages: {', '.join(decision.packages)}", file=sys.stderr)
        return 1

    return subprocess.run(list(argv), check=False).returncode


def _main_wrapper(program_name: str, argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog=f"pkgguard-{program_name}",
        description=f"Run {program_name} only after pkgguard authorizes package installs.",
    )
    parser.add_argument("--allow-review", action="store_true", help="Permit REVIEW outcomes after a human approval step.")
    parser.add_argument(
        "--new-package-policy",
        choices=("block", "review"),
        default=None,
        help="Policy for very new packages.",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help=f"Command to run with {program_name}, e.g. install express")
    args = parser.parse_args(argv)
    if not args.command:
        parser.error("a command is required")
    allow_review = args.allow_review or _env_bool("PKGGUARD_ALLOW_REVIEW", False)
    new_package_policy = args.new_package_policy or _env_policy("block")
    program_argv = [program_name, *args.command]
    if not _is_install_command(program_name, args.command):
        return subprocess.run(program_argv, check=False).returncode
    return run_guarded(program_argv, allow_review=allow_review, new_package_policy=new_package_policy)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pkgguard-gate",
        description="Run a package-manager install command only after pkgguard authorizes it.",
    )
    parser.add_argument("--allow-review", action="store_true", help="Permit REVIEW outcomes after a human approval step.")
    parser.add_argument(
        "--new-package-policy",
        choices=("block", "review"),
        default=None,
        help="Policy for very new packages.",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run, e.g. npm install react-codeshift")

    args = parser.parse_args(argv)
    if not args.command:
        parser.error("a command is required")
    allow_review = args.allow_review or _env_bool("PKGGUARD_ALLOW_REVIEW", False)
    new_package_policy = args.new_package_policy or _env_policy("block")
    return run_guarded(args.command, allow_review=allow_review, new_package_policy=new_package_policy)


def main_npm(argv: Sequence[str] | None = None) -> int:
    return _main_wrapper("npm", argv)


def main_yarn(argv: Sequence[str] | None = None) -> int:
    return _main_wrapper("yarn", argv)


def main_pnpm(argv: Sequence[str] | None = None) -> int:
    return _main_wrapper("pnpm", argv)


def main_bun(argv: Sequence[str] | None = None) -> int:
    return _main_wrapper("bun", argv)


def main_pip(argv: Sequence[str] | None = None) -> int:
    return _main_wrapper("pip", argv)


def main_pip3(argv: Sequence[str] | None = None) -> int:
    return _main_wrapper("pip3", argv)


def main_uv(argv: Sequence[str] | None = None) -> int:
    return _main_wrapper("uv", argv)


def main_poetry(argv: Sequence[str] | None = None) -> int:
    return _main_wrapper("poetry", argv)


def main_cargo(argv: Sequence[str] | None = None) -> int:
    return _main_wrapper("cargo", argv)


if __name__ == "__main__":
    raise SystemExit(main())
