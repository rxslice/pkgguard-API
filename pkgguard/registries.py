"""
pkgguard — built by Blvkware (https://blvkware.dev)
Licensed under the Apache License 2.0. See LICENSE.
Live registry clients.

All three registries expose free, unauthenticated, public JSON APIs. There is
no data-licensing cost and no API key to obtain — that is deliberate: it keeps
this project free to run and free to self-host.

Every client returns a normalized `PackageFacts` so the scoring engine does not
need to know which ecosystem it is looking at.
"""
from __future__ import annotations

import json
import hashlib
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

USER_AGENT = "pkgguard/0.1 (+https://github.com/rxslice/pkgguard-API)"
TIMEOUT = 10
RETRIES = 2
CACHE_TTL = 300
PYPI_STATS_CIRCUIT_SECONDS = 300
_pypi_stats_blocked_until = 0.0


@dataclass
class PackageFacts:
    name: str
    ecosystem: str
    exists: bool
    created: Optional[str] = None          # ISO8601
    age_days: Optional[int] = None
    version_count: Optional[int] = None
    monthly_downloads: Optional[int] = None
    description: Optional[str] = None
    repository: Optional[str] = None
    maintainer_count: Optional[int] = None
    fetch_error: Optional[str] = None
    download_stats_error: Optional[str] = None


class RateLimitedError(RuntimeError):
    """A registry explicitly rejected the request due to rate limiting."""


def _cache_path(url: str) -> str:
    root = os.environ.get(
        "PKGGUARD_CACHE_DIR",
        os.path.join(os.path.expanduser("~"), ".cache", "pkgguard"),
    )
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, hashlib.sha256(url.encode("utf-8")).hexdigest() + ".json")


def _get_json(
    url: str,
    *,
    retry_rate_limit: bool = True,
    cache_rate_limit: bool = False,
) -> Optional[dict]:
    try:
        cache = _cache_path(url)
    except OSError:
        cache = ""
    try:
        if cache and time.time() - os.path.getmtime(cache) <= CACHE_TTL:
            with open(cache, encoding="utf-8") as stream:
                cached = json.load(stream)
            if isinstance(cached, dict) and cached.get("__pkgguard_rate_limited__"):
                raise RateLimitedError(f"{url} rate limit is cached")
            return cached
    except (OSError, ValueError):
        pass

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    last_error = None
    for attempt in range(RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                data = json.load(resp)
            if cache:
                try:
                    temp = cache + ".tmp"
                    with open(temp, "w", encoding="utf-8") as stream:
                        json.dump(data, stream)
                    os.replace(temp, cache)
                except OSError:
                    pass
            return data
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            if error.code == 429 and not retry_rate_limit:
                if cache_rate_limit and cache:
                    try:
                        with open(cache, "w", encoding="utf-8") as stream:
                            json.dump({"__pkgguard_rate_limited__": True}, stream)
                    except OSError:
                        pass
                raise RateLimitedError(f"{url} returned HTTP 429")
            last_error = error
        except Exception as error:
            last_error = error
        if attempt < RETRIES:
            time.sleep(0.25 * (2 ** attempt))
    raise last_error


def _age_days(iso: Optional[str]) -> Optional[int]:
    if not iso:
        return None
    try:
        cleaned = iso.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


# --------------------------------------------------------------------------
# npm
# --------------------------------------------------------------------------

def fetch_npm(name: str) -> PackageFacts:
    safe = urllib.parse.quote(name, safe="@")
    try:
        data = _get_json(f"https://registry.npmjs.org/{safe}")
    except Exception as e:
        return PackageFacts(name, "npm", exists=False, fetch_error=f"registry unreachable: {e}")

    if data is None:
        return PackageFacts(name, "npm", exists=False)

    time_info = data.get("time", {}) or {}
    created = time_info.get("created")
    versions = data.get("versions", {}) or {}

    downloads = None
    try:
        dl = _get_json(f"https://api.npmjs.org/downloads/point/last-month/{safe}")
        if dl:
            downloads = dl.get("downloads")
    except Exception:
        pass  # download stats are a bonus signal, not required

    repo = data.get("repository")
    repo_url = repo.get("url") if isinstance(repo, dict) else (repo if isinstance(repo, str) else None)

    return PackageFacts(
        name=name,
        ecosystem="npm",
        exists=True,
        created=created,
        age_days=_age_days(created),
        version_count=len(versions),
        monthly_downloads=downloads,
        description=data.get("description"),
        repository=repo_url,
        maintainer_count=len(data.get("maintainers", []) or []),
    )


# --------------------------------------------------------------------------
# PyPI
# --------------------------------------------------------------------------

def fetch_pypi(name: str) -> PackageFacts:
    safe = urllib.parse.quote(name)
    try:
        data = _get_json(f"https://pypi.org/pypi/{safe}/json")
    except Exception as e:
        return PackageFacts(name, "pypi", exists=False, fetch_error=f"registry unreachable: {e}")

    if data is None:
        return PackageFacts(name, "pypi", exists=False)

    info = data.get("info", {}) or {}
    releases = data.get("releases", {}) or {}

    # Earliest upload time across all releases = package creation.
    created = None
    times = []
    for files in releases.values():
        for f in files or []:
            t = f.get("upload_time_iso_8601") or f.get("upload_time")
            if t:
                times.append(t)
    if times:
        created = min(times)

    downloads = None
    download_stats_error = None
    global _pypi_stats_blocked_until
    try:
        stats_url = f"https://pypistats.org/api/packages/{safe}/recent"
        if time.monotonic() < _pypi_stats_blocked_until:
            raise RateLimitedError("pypistats circuit breaker is open")
        stats = _get_json(stats_url, retry_rate_limit=False, cache_rate_limit=True)
        downloads = (stats or {}).get("data", {}).get("last_month")
    except RateLimitedError as error:
        _pypi_stats_blocked_until = time.monotonic() + PYPI_STATS_CIRCUIT_SECONDS
        download_stats_error = str(error)
    except (OSError, urllib.error.URLError, ValueError) as error:
        download_stats_error = f"download statistics unavailable: {error}"

    return PackageFacts(
        name=name,
        ecosystem="pypi",
        exists=True,
        created=created,
        age_days=_age_days(created),
        version_count=len(releases),
        monthly_downloads=downloads,
        download_stats_error=download_stats_error,
        description=(info.get("summary") or None),
        repository=(info.get("project_urls") or {}).get("Source") or info.get("home_page"),
        maintainer_count=None,
    )


# --------------------------------------------------------------------------
# crates.io
# --------------------------------------------------------------------------

def fetch_crates(name: str) -> PackageFacts:
    safe = urllib.parse.quote(name)
    try:
        data = _get_json(f"https://crates.io/api/v1/crates/{safe}")
    except Exception as e:
        return PackageFacts(name, "crates", exists=False, fetch_error=f"registry unreachable: {e}")

    if data is None or "crate" not in data:
        return PackageFacts(name, "crates", exists=False)

    crate = data["crate"]
    created = crate.get("created_at")

    return PackageFacts(
        name=name,
        ecosystem="crates",
        exists=True,
        created=created,
        age_days=_age_days(created),
        version_count=len(data.get("versions", []) or []),
        monthly_downloads=crate.get("recent_downloads"),
        description=crate.get("description"),
        repository=crate.get("repository"),
        maintainer_count=None,
    )


FETCHERS = {"npm": fetch_npm, "pypi": fetch_pypi, "crates": fetch_crates}
SUPPORTED_ECOSYSTEMS = tuple(FETCHERS.keys())


def fetch(name: str, ecosystem: str) -> PackageFacts:
    eco = ecosystem.lower().strip()
    fetcher = FETCHERS.get(eco)
    if fetcher is None:
        raise ValueError(f"Unsupported ecosystem '{ecosystem}'. Supported: {SUPPORTED_ECOSYSTEMS}")
    return fetcher(name)
