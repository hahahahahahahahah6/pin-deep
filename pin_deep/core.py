"""Core logic for pin-deep: parse ``uses:`` references, classify pin status,
and recursively scan the ``action.yml`` of SHA-pinned actions.

stdlib-only (urllib for GitHub fetching).
"""
from __future__ import annotations

import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from . import __version__

# Matches `uses: <value>` lines, with or without a YAML list dash and quotes.
_USES_RE = re.compile(
    r"""^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*"""
    r"""(?:"([^"\n]+)"|'([^'\n]+)'|([^ \t\n#]+))""",
    re.MULTILINE | re.VERBOSE,
)

_FULL_SHA_RE = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_SHORT_SHA_RE = re.compile(r"[0-9a-fA-F]{7,39}")


def find_uses_values(text: str) -> list[str]:
    """Return every raw ``uses:`` value found in YAML-ish text (workflows and action.yml)."""
    out: list[str] = []
    for match in _USES_RE.finditer(text):
        value = match.group(1) or match.group(2) or match.group(3)
        if value:
            out.append(value.strip())
    return out


@dataclass
class UsesRef:
    raw: str
    kind: str  # "action" | "local" | "docker" | "dynamic" | "invalid"
    owner: str = ""
    repo: str = ""
    subpath: str = ""
    ref: str | None = None
    status: str = "unknown"  # pinned | unpinned | short-sha | skipped | dynamic | invalid


def parse_uses(value: str) -> UsesRef:
    """Parse one ``uses:`` value and classify how (un)pinned it is."""
    raw = value.strip().strip("\"'")
    if not raw or "${{" in raw:
        return UsesRef(raw=value, kind="dynamic", status="dynamic")
    if raw.startswith("docker://"):
        return UsesRef(raw=value, kind="docker", status="skipped")
    if raw.startswith("./") or raw.startswith("../"):
        return UsesRef(raw=value, kind="local", status="skipped")
    if "@" in raw:
        head, ref = raw.rsplit("@", 1)
    else:
        head, ref = raw, None
    parts = head.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return UsesRef(raw=value, kind="invalid", status="invalid")
    owner, repo, subpath = parts[0], parts[1], "/".join(parts[2:])
    parsed = UsesRef(raw=value, kind="action", owner=owner, repo=repo,
                     subpath=subpath, ref=ref)
    if ref is None:
        parsed.status = "unpinned"
    elif _FULL_SHA_RE.fullmatch(ref):
        parsed.status = "pinned"
    elif _SHORT_SHA_RE.fullmatch(ref):
        parsed.status = "short-sha"
    else:
        parsed.status = "unpinned"
    return parsed


@dataclass
class Finding:
    uses: str
    owner: str = ""
    repo: str = ""
    ref: str | None = None
    status: str = "unpinned"  # unpinned | short-sha | error
    depth: int = 0
    chain: list[str] = field(default_factory=list)
    source: str = ""
    note: str = ""


class GitHubFetcher:
    """Fetch an action's ``action.yml`` from GitHub with urllib only.

    Tries raw.githubusercontent.com first (no auth needed for public repos),
    then the REST API (supports ``GITHUB_TOKEN`` for private repos / rate limits).
    """

    def __init__(self, token: str | None = None, timeout: int = 20) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.timeout = timeout
        self.last_error = ""
        self.fetch_count = 0

    def get_action_yml(self, owner: str, repo: str, ref: str, subpath: str = "") -> str | None:
        self.last_error = ""
        base = f"{subpath}/" if subpath else ""
        for name in ("action.yml", "action.yaml"):
            text = self._get(
                f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{base}{name}")
            if text is not None:
                self.fetch_count += 1
                return text
        # Fall back to the contents API (also covers private repos with a token).
        text = self._get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{base}action.yml?ref={ref}",
            headers={"Accept": "application/vnd.github.raw"})
        if text is not None:
            self.fetch_count += 1
        return text

    def _get(self, url: str, headers: dict | None = None) -> str | None:
        req_headers = {"User-Agent": f"pin-deep/{__version__}"}
        if self.token and "api.github.com" in url:
            req_headers["Authorization"] = f"Bearer {self.token}"
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            self.last_error = f"HTTP {exc.code} for {url}"
        except (urllib.error.URLError, OSError) as exc:
            self.last_error = f"network error: {exc}"
        return None


class Scanner:
    """Recursively scan ``uses:`` references, following only full-SHA pins.

    Unpinned references are flagged but never recursed into: a moving tag has
    no fixed content to analyze, so its children are a moving target too.
    """

    def __init__(self, fetcher: GitHubFetcher | None = None, max_depth: int = 3) -> None:
        self.fetcher = fetcher or GitHubFetcher()
        self.max_depth = max_depth
        self.findings: list[Finding] = []
        self._visited: set[tuple[str, str, str, str]] = set()

    def scan_ref(self, uses_value: str, source: str = "<input>") -> list[Finding]:
        self._scan(parse_uses(uses_value), source=source, depth=0, chain=[])
        return self.findings

    def scan_text(self, text: str, source: str = "<input>") -> list[Finding]:
        for value in find_uses_values(text):
            self.scan_ref(value, source=source)
        return self.findings

    def scan_file(self, path: str) -> list[Finding]:
        with open(path, encoding="utf-8") as fh:
            return self.scan_text(fh.read(), source=path)

    def _scan(self, ref: UsesRef, source: str, depth: int, chain: list[str]) -> None:
        if ref.kind != "action":
            return
        if ref.status in ("unpinned", "short-sha"):
            self.findings.append(Finding(
                uses=ref.raw, owner=ref.owner, repo=ref.repo, ref=ref.ref,
                status=ref.status, depth=depth, chain=[*chain, ref.raw],
                source=source,
                note="not pinned to a full commit SHA" if ref.status == "unpinned"
                     else "short SHA is weaker than a full 40/64-char SHA"))
            return
        if ref.status != "pinned":
            return
        key = (ref.owner.lower(), ref.repo.lower(), ref.ref or "", ref.subpath)
        if key in self._visited:
            return
        self._visited.add(key)
        if depth >= self.max_depth:
            return
        text = self.fetcher.get_action_yml(ref.owner, ref.repo, ref.ref or "", ref.subpath)
        if text is None:
            self.findings.append(Finding(
                uses=ref.raw, owner=ref.owner, repo=ref.repo, ref=ref.ref,
                status="error", depth=depth, chain=[*chain, ref.raw],
                source=source,
                note=self.fetcher.last_error or "could not fetch action.yml"))
            return
        child_source = f"action.yml of {ref.owner}/{ref.repo}@{ref.ref}"
        for value in find_uses_values(text):
            self._scan(parse_uses(value), source=child_source,
                       depth=depth + 1, chain=[*chain, ref.raw])
