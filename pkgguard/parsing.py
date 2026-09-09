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
    "--audit", "--exact", "--global", "--legacy-peer-deps", "--no-audit",
    "--no-fund", "--no-save", "--save", "--save-dev", "--save-exact",
    "--upgrade", "--user", "--verbose", "-D", "-E", "-U", "-d", "-q",
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
            return True
    return False


def parse_install_command(cmd: str) -> Tuple[Optional[str], List[str]]:
    """Extract (ecosystem, package_names) from a shell install command."""
    for pattern, ecosystem in _INSTALL_PATTERNS:
        match = pattern.search(cmd)
        if not match:
            continue
        names: List[str] = []
        for token in match.group(1).split():
            token = token.strip().strip("\"'")
            if not token or _FLAG.match(token):
                continue
            token = re.split(r"[><=~!]+", token)[0]
            if token.startswith("@"):
                parts = token.split("@")
                token = "@" + parts[1] if len(parts) > 1 else token
            else:
                token = token.split("@")[0]
            token = token.strip()
            if not token or ("/" in token and not token.startswith("@")):
                continue
            if token.startswith(".") or "://" in token:
                continue
            names.append(token)
        return ecosystem, names
    return None, []
