"""Parsing helpers for package-manager commands and manifests."""
from __future__ import annotations

import re
import shlex
from typing import List, Optional, Tuple

_INSTALL_PATTERNS = [
    (re.compile(r"\bnpm\s+(?:i|install|add)\s+(.+)", re.I), "npm"),
    (re.compile(r"\b(?:yarn|pnpm|bun)\s+add\s+(.+)", re.I), "npm"),
    (re.compile(r"\bpip3?\s+install\s+(.+)", re.I), "pypi"),
    (re.compile(r"\buv\s+(?:pip\s+)?(?:install|add)\s+(.+)", re.I), "pypi"),
    (re.compile(r"\bpoetry\s+add\s+(.+)", re.I), "pypi"),
    (re.compile(r"\bcargo\s+add\s+(.+)", re.I), "crates"),
]
_FLAG = re.compile(r"^-")
_KNOWN_FLAGS = {
    "--audit", "--dev", "--exact", "--global", "--global-style",
    "--legacy-peer-deps", "--no-audit", "--no-cache-dir", "--no-fund",
    "--no-optional", "--no-save", "--prefer-offline", "--production",
    "--save", "--save-dev", "--save-exact", "--upgrade", "--user",
    "--verbose", "-D", "-E", "-U", "-d", "-g", "-q",
}


def has_unsupported_flag(cmd: str) -> bool:
    """Return True when a command contains a flag not explicitly allowlisted."""
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        return True
    for token in tokens:
        normalized = token.lower()
        if normalized.startswith("-") and normalized not in _KNOWN_FLAGS:
            if normalized.startswith("--omit="):
                continue
            return True
    return False


# An operand that names something other than a registry package: a path, a
# URL, a git or GitHub reference, a local archive, or an npm alias
# (`lodash@npm:other` installs `other` under the name `lodash`). None of these
# can be verified against a registry, so they must never be silently dropped:
# dropping one let `npm install express ./unverified` come back ALLOW.
_ARCHIVE = re.compile(r"\.(?:tgz|tar\.gz|tar\.bz2|tar|zip|whl|egg|crate)$", re.I)


def _unverifiable(token: str) -> bool:
    t = token
    if t in {"@", "."} or t.startswith((".", "/", "~", "\\")):
        return True
    if "://" in t or ":" in t:  # URLs, git+, file:, github:, npm:, workspace:, C:\
        return True
    if _ARCHIVE.search(t):
        return True
    if "/" in t:
        # npm scoped names are @scope/name; anything else with a slash is a
        # path or a GitHub user/repo shorthand.
        return not (t.startswith("@") and t.count("/") == 1)
    return False


def parse_install_operands(cmd: str) -> Tuple[Optional[str], List[str], List[str]]:
    """Extract (ecosystem, package_names, unverifiable_operands) from a command.

    Every non-flag operand ends up in exactly one of the two lists.
    """
    for pattern, ecosystem in _INSTALL_PATTERNS:
        match = pattern.search(cmd)
        if not match:
            continue
        names: List[str] = []
        unverifiable: List[str] = []
        for raw in match.group(1).split():
            raw = raw.strip().strip("\"'")
            if not raw or _FLAG.match(raw):
                continue
            if _unverifiable(raw):
                unverifiable.append(raw)
                continue
            token = re.split(r"[\[><=~!;]+", raw)[0]
            if token.startswith("@"):
                parts = token.split("@")
                token = "@" + parts[1] if len(parts) > 1 else token
            else:
                token = token.split("@")[0]
            token = token.strip()
            if not token:
                unverifiable.append(raw)
                continue
            names.append(token)
        return ecosystem, names, unverifiable
    return None, [], []


def parse_install_command(cmd: str) -> Tuple[Optional[str], List[str]]:
    """Extract (ecosystem, package_names) from a shell install command.

    Operands that are not registry names are left out; callers that decide
    whether a command is safe must use parse_install_operands instead.
    """
    ecosystem, names, _ = parse_install_operands(cmd)
    return ecosystem, names
