#!/usr/bin/env python3
"""Shared helpers for the dependency-audit scripts.

Standard library only, Python 3.11 or later (tomllib). Every script inserts its own directory at
the front of sys.path before importing this module, so it also works under `python -I`.

Contents: run-directory paths, JSON I/O, an HTTP client (timeouts, retries, gzip, per-host
throttling, an offline switch), a reader for the YAML subset that lockfiles and the rules files
use, purl and version helpers, credential redaction, the project walker, prompt-injection lead
detection and a CVSS v3 base-score calculator.
"""
from __future__ import annotations

import datetime as _dt
import functools
import gzip
import json
import math
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

if sys.version_info < (3, 11):  # pragma: no cover - checked before anything else runs
    sys.exit("dependency-audit needs Python 3.11 or later (found %d.%d)." % sys.version_info[:2])

TOOL_NAME = "dependency-audit"
TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0.0"
USER_AGENT = "%s/%s (+python-urllib)" % (TOOL_NAME, TOOL_VERSION)
SKILL_DIR = Path(__file__).resolve().parent.parent
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SUPPORT_STATUSES = ["supported", "security-only", "end-of-life", "deprecated", "unmaintained", "unknown"]
OUT_OF_SUPPORT = {"end-of-life", "deprecated", "unmaintained"}

for _stream in (sys.stdout, sys.stderr):  # report text includes "…"; never crash on a legacy console
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


# --------------------------------------------------------------------------- time, paths, JSON

def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def iso(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return iso(utc_now())


def today() -> _dt.date:
    return utc_now().date()


def raw_dir(out) -> Path:
    return Path(out) / "raw"


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data) -> None:
    """Write JSON atomically (temp file, then rename), UTF-8, 2-space indent."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def posix(path) -> str:
    return str(path).replace("\\", "/")


def read_text(path, limit: int | None = None) -> str:
    """Read a text file leniently (UTF-8 with BOM handling, undecodable bytes replaced)."""
    data = Path(path).read_bytes()
    if limit is not None:
        data = data[:limit]
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def load_rules(name: str):
    """Load rules/<name>.yaml from the skill package."""
    return load_yaml(read_text(SKILL_DIR / "rules" / ("%s.yaml" % name)))


# --------------------------------------------------------------------------- HTTP

class FetchError(Exception):
    def __init__(self, url: str, message: str, status: int | None = None):
        super().__init__("%s: %s" % (url, message))
        self.url = url
        self.message = message
        self.status = status


_OFFLINE = False
_SSL = ssl.create_default_context()
_THROTTLE_LOCK = threading.Lock()
_HOST_LOCKS: dict[str, threading.Lock] = {}
_HOST_LAST: dict[str, float] = {}
# Minimum seconds between requests to one host. crates.io asks crawlers for at most one request a second.
HOST_MIN_INTERVAL = {"crates.io": 1.0, "api.github.com": 0.25, "gitlab.com": 0.25}


def set_offline(flag: bool) -> None:
    """With offline set, every request fails at once without touching the network (hard rule 2)."""
    global _OFFLINE
    _OFFLINE = bool(flag)


def _throttle(host: str) -> None:
    interval = HOST_MIN_INTERVAL.get(host)
    if not interval:
        return
    with _THROTTLE_LOCK:
        lock = _HOST_LOCKS.setdefault(host, threading.Lock())
    with lock:
        wait = _HOST_LAST.get(host, 0.0) + interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _HOST_LAST[host] = time.monotonic()


def http_request(url: str, *, data=None, headers=None, timeout: float = 20, retries: int = 2, method: str | None = None):
    """Return (status, body bytes, headers). Raises FetchError. 404 is never retried."""
    if _OFFLINE:
        raise FetchError(url, "offline mode")
    host = urllib.parse.urlsplit(url).hostname or ""
    hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
    hdrs.update(headers or {})
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    last_error = "unknown error"
    for attempt in range(retries + 1):
        _throttle(host)
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method or ("POST" if body is not None else "GET"))
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding", "").lower() == "gzip" or raw[:2] == b"\x1f\x8b":
                    raw = gzip.decompress(raw)
                return resp.status, raw, resp.headers
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise FetchError(url, "not found (HTTP 404)", 404)
            last_error = "HTTP %d" % e.code
            if e.code in (403, 429, 500, 502, 503, 504) and attempt < retries:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                delay = float(retry_after) if retry_after and retry_after.isdigit() else 2.0 ** (attempt + 1)
                if e.code == 403 and host != "api.github.com":
                    raise FetchError(url, last_error, e.code)
                time.sleep(min(delay, 20.0))
                continue
            raise FetchError(url, last_error, e.code)
        except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError, OSError) as e:
            reason = getattr(e, "reason", None) or e
            last_error = "%s: %s" % (type(e).__name__, reason)
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise FetchError(url, last_error)
    raise FetchError(url, last_error)


def get_json(url: str, **kw):
    _, raw, _ = http_request(url, **kw)
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as e:
        raise FetchError(url, "response is not JSON (%s)" % e)


def get_text(url: str, **kw) -> str:
    _, raw, _ = http_request(url, **kw)
    return raw.decode("utf-8", errors="replace")


def post_json(url: str, payload, **kw):
    _, raw, _ = http_request(url, data=payload, **kw)
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as e:
        raise FetchError(url, "response is not JSON (%s)" % e)


def host_reachable(url: str, timeout: float = 8) -> tuple[bool, str]:
    """One plain HTTPS request. Any HTTP status counts as reachable; only connection errors don't."""
    try:
        http_request(url, timeout=timeout, retries=0)
        return True, "reachable"
    except FetchError as e:
        if e.status is not None:
            return True, "reachable (HTTP %d)" % e.status
        return False, e.message


# --------------------------------------------------------------------------- YAML subset

class YamlError(ValueError):
    pass


def load_yaml(text: str):
    """Parse the YAML subset used by lockfiles (pnpm, Yarn Berry, pubspec, Podfile) and this skill's
    rules files: block mappings and sequences, flow [..] and {..}, quoted and plain scalars, block
    scalars, comments. Plain scalars stay strings, so a version like 1.10 is never turned into a
    number; true/false become booleans and null/~ become None. Anchors, aliases and tags are not
    interpreted."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").replace("\t", "    ").split("\n")
    return _YamlParser(lines).parse()


def _find_closing_quote(s: str, start: int) -> int | None:
    q = s[start]
    j = start + 1
    while j < len(s):
        c = s[j]
        if q == '"' and c == "\\":
            j += 2
            continue
        if c == q:
            if q == "'" and j + 1 < len(s) and s[j + 1] == "'":
                j += 2
                continue
            return j
        j += 1
    return None


def _strip_comment(s: str) -> str:
    j = 0
    while j < len(s):
        c = s[j]
        if c in "'\"" and (j == 0 or s[j - 1] in " \t[{,:"):
            end = _find_closing_quote(s, j)
            if end is None:
                return s
            j = end + 1
            continue
        if c == "#" and (j == 0 or s[j - 1] in " \t"):
            return s[:j].rstrip()
        j += 1
    return s


def _dq_unescape(s: str) -> str:
    out, j = [], 0
    simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", '"': '"', "\\": "\\", "/": "/", " ": " ", "e": "\x1b", "a": "\a", "b": "\b"}
    while j < len(s):
        c = s[j]
        if c != "\\" or j + 1 >= len(s):
            out.append(c)
            j += 1
            continue
        n = s[j + 1]
        if n in simple:
            out.append(simple[n])
            j += 2
        elif n in "xuU":
            width = {"x": 2, "u": 4, "U": 8}[n]
            try:
                out.append(chr(int(s[j + 2:j + 2 + width], 16)))
            except ValueError:
                out.append(s[j:j + 2 + width])
            j += 2 + width
        else:
            out.append(n)
            j += 2
    return "".join(out)


def _yaml_scalar(s: str):
    s = s.strip()
    if not s:
        return None
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return _dq_unescape(s[1:-1])
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if s in ("null", "Null", "NULL", "~"):
        return None
    return s


def _is_seq_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _split_key(s: str):
    """Return (key, rest) when s is a 'key: value' or 'key:' entry, else None."""
    if not s or s[0] in "[{#" or _is_seq_item(s):
        return None
    if s[0] in "'\"":
        end = _find_closing_quote(s, 0)
        if end is None:
            return None
        m = re.match(r"\s*:(?=\s|$)", s[end + 1:])
        if not m:
            return None
        return _yaml_scalar(s[:end + 1]), s[end + 1 + m.end():]
    for j, c in enumerate(s):
        if c == ":" and (j + 1 == len(s) or s[j + 1] in " \t"):
            key = s[:j].rstrip()
            return (key, s[j + 1:]) if key else None
        if c == "#" and j > 0 and s[j - 1] in " \t":
            return None
    return None


def _flow_balanced(s: str) -> bool:
    depth, j = 0, 0
    while j < len(s):
        c = s[j]
        if c in "'\"":
            end = _find_closing_quote(s, j)
            if end is None:
                return False
            j = end + 1
            continue
        if c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        j += 1
    return depth <= 0


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t\n":
        i += 1
    return i


def _parse_flow(s: str, i: int):
    i = _skip_ws(s, i)
    if i >= len(s):
        raise YamlError("unexpected end of flow collection")
    c = s[i]
    if c == "[":
        out, i = [], i + 1
        while True:
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == "]":
                return out, i + 1
            value, i = _parse_flow(s, i)
            out.append(value)
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == ",":
                i += 1
            elif i < len(s) and s[i] == "]":
                return out, i + 1
            else:
                raise YamlError("expected ',' or ']' in flow sequence")
    if c == "{":
        out, i = {}, i + 1
        while True:
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == "}":
                return out, i + 1
            key, i = _parse_flow_scalar(s, i, True)
            i = _skip_ws(s, i)
            value = None
            if i < len(s) and s[i] == ":":
                value, i = _parse_flow(s, i + 1)
            out[key] = value
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == ",":
                i += 1
            elif i < len(s) and s[i] == "}":
                return out, i + 1
            else:
                raise YamlError("expected ',' or '}' in flow mapping")
    return _parse_flow_scalar(s, i, False)


def _parse_flow_scalar(s: str, i: int, is_key: bool):
    if s[i] in "'\"":
        end = _find_closing_quote(s, i)
        if end is None:
            raise YamlError("unterminated quoted scalar")
        return _yaml_scalar(s[i:end + 1]), end + 1
    j = i
    while j < len(s):
        c = s[j]
        if c in ",]}":
            break
        if c == ":" and (j + 1 >= len(s) or s[j + 1] in " ,]}"):
            break
        j += 1
    return _yaml_scalar(s[i:j]), j


class _YamlParser:
    def __init__(self, lines: list[str]):
        self.lines = lines
        self.i = 0

    def _peek(self):
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            st = raw.strip()
            if not st or st.startswith("#") or st in ("---", "...") or st.startswith("%"):
                self.i += 1
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            return indent, raw[indent:]
        return None

    def parse(self):
        nxt = self._peek()
        return None if nxt is None else self._node(nxt[0])

    def _node(self, indent: int):
        nxt = self._peek()
        if nxt is None or nxt[0] < indent:
            return None
        ind, content = nxt
        if _is_seq_item(content):
            return self._seq(ind)
        if _split_key(content) is not None:
            return self._map(ind)
        self.i += 1
        return self._value(ind, _strip_comment(content).strip())

    def _value(self, indent: int, text: str):
        if not text:
            return None
        if text[0] in "|>":
            return self._block_scalar(indent, text)
        if text[0] in "[{":
            while not _flow_balanced(text) and self.i < len(self.lines):
                text += " " + _strip_comment(self.lines[self.i].strip())
                self.i += 1
            try:
                return _parse_flow(text, 0)[0]
            except (YamlError, IndexError) as e:
                raise YamlError("line %d: bad flow collection (%s)" % (self.i, e))
        return _yaml_scalar(text)

    def _map(self, indent: int) -> dict:
        out = {}
        while True:
            nxt = self._peek()
            if nxt is None or nxt[0] != indent or _is_seq_item(nxt[1]):
                return out
            kv = _split_key(nxt[1])
            if kv is None:
                raise YamlError("line %d: expected 'key: value'" % (self.i + 1))
            key, rest = kv
            self.i += 1
            rest = _strip_comment(rest).strip()
            if rest:
                out[key] = self._value(indent, rest)
                continue
            nxt2 = self._peek()
            if nxt2 is not None and nxt2[0] > indent:
                out[key] = self._node(nxt2[0])
            elif nxt2 is not None and nxt2[0] == indent and _is_seq_item(nxt2[1]):
                out[key] = self._seq(indent)
            else:
                out[key] = None

    def _seq(self, indent: int) -> list:
        out = []
        while True:
            nxt = self._peek()
            if nxt is None or nxt[0] != indent or not _is_seq_item(nxt[1]):
                return out
            rest = nxt[1][1:]
            body = rest.lstrip(" ")
            col = indent + 1 + (len(rest) - len(body))
            if not body or body.startswith("#"):
                self.i += 1
                nxt2 = self._peek()
                out.append(self._node(nxt2[0]) if nxt2 is not None and nxt2[0] > indent else None)
                continue
            if _is_seq_item(body) or _split_key(body) is not None:
                self.lines[self.i] = " " * col + body  # parse the inline collection at its own column
                out.append(self._node(col))
                continue
            self.i += 1
            out.append(self._value(indent, _strip_comment(body).strip()))

    def _block_scalar(self, parent_indent: int, header: str) -> str:
        style = header[0]
        chomp = "strip" if "-" in header else ("keep" if "+" in header else "clip")
        body, block_indent = [], None
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if not raw.strip():
                body.append("")
                self.i += 1
                continue
            ind = len(raw) - len(raw.lstrip(" "))
            if ind <= parent_indent or (block_indent is not None and ind < block_indent):
                break
            if block_indent is None:
                block_indent = ind
            body.append(raw[block_indent:])
            self.i += 1
        while body and body[-1] == "" and chomp != "keep":
            body.pop()
        if style == "|":
            text = "\n".join(body)
        else:
            paras, cur = [], []
            for line in body:
                if line == "":
                    paras.append(" ".join(cur))
                    cur = []
                else:
                    cur.append(line.strip())
            paras.append(" ".join(cur))
            text = "\n".join(paras)
        return text if chomp == "strip" else text + "\n"


def load_jsonc(text: str):
    """JSON with // and /* */ comments and trailing commas (bun.lock, some tool configs)."""
    out, j, n = [], 0, len(text)
    while j < n:
        c = text[j]
        if c == '"':
            k = j + 1
            while k < n and text[k] != '"':
                k += 2 if text[k] == "\\" else 1
            out.append(text[j:k + 1])
            j = k + 1
        elif text.startswith("//", j):
            k = text.find("\n", j)
            j = n if k < 0 else k
        elif text.startswith("/*", j):
            k = text.find("*/", j + 2)
            j = n if k < 0 else k + 2
        else:
            out.append(c)
            j += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned)


# --------------------------------------------------------------------------- purl, ecosystems

OSV_ECOSYSTEMS = {"npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "Packagist", "NuGet", "Pub", "SwiftURL"}
PURL_TYPES = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "golang", "crates.io": "cargo",
              "RubyGems": "gem", "Packagist": "composer", "NuGet": "nuget", "Pub": "pub",
              "CocoaPods": "cocoapods", "SwiftURL": "swift"}


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pct(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def make_purl(ecosystem: str, name: str, version: str | None) -> str:
    t = PURL_TYPES.get(ecosystem, ecosystem.lower())
    if t == "npm" and name.startswith("@") and "/" in name:
        scope, nm = name.split("/", 1)
        path = _pct(scope) + "/" + _pct(nm)
    elif t == "pypi":
        path = _pct(normalize_pypi(name))
    elif t == "maven" and ":" in name:
        g, a = name.split(":", 1)
        path = _pct(g) + "/" + _pct(a)
    elif t in ("golang", "swift"):
        path = "/".join(_pct(seg) for seg in name.split("/"))
    elif t == "composer" and "/" in name:
        v, n = name.split("/", 1)
        path = _pct(v.lower()) + "/" + _pct(n.lower())
    else:
        path = _pct(name)
    purl = "pkg:%s/%s" % (t, path)
    return purl + "@" + _pct(version) if version else purl


# --------------------------------------------------------------------------- versions

_VER_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_PRE_TAGS = {"snapshot": -6, "dev": -5, "alpha": -4, "a": -4, "m": -4, "milestone": -4, "beta": -3, "b": -3,
             "preview": -2, "pre": -2, "c": -1, "rc": -1, "cr": -1}
_NEUTRAL_TAGS = {"final", "ga", "release", "r"}
_POST_TAGS = {"post", "sp", "p", "patch", "pl"}


def _version_parts(v: str):
    """Split a version into its numeric release (trailing zeros dropped) and a suffix list where
    pre-release tags sort low (0), numbers high (2) and post-release tags higher (3)."""
    v = (v or "").strip()
    v = re.sub(r"^[vV=]+", "", v).split("+", 1)[0]
    tokens = _VER_TOKEN.findall(v)
    release, i = [], 0
    while i < len(tokens) and tokens[i].isdigit():
        release.append(int(tokens[i]))
        i += 1
    while release and release[-1] == 0:
        release.pop()
    suffix = []
    for tok in tokens[i:]:
        if tok.isdigit():
            suffix.append((2, int(tok), ""))
            continue
        t = tok.lower()
        if t in _NEUTRAL_TAGS:
            continue
        suffix.append((3, 0, t) if t in _POST_TAGS else (0, _PRE_TAGS.get(t, 0), t))
    return release, suffix


def compare_versions(a: str, b: str) -> int:
    """Approximate ordering that works for semver, PEP 440, Maven, NuGet, RubyGems and Go versions.
    Used to choose the fixed version that applies and to spot a newer major, never to decide
    whether a version is affected (OSV.dev does that)."""
    (ra, sa), (rb, sb) = _version_parts(a), _version_parts(b)
    n = max(len(ra), len(rb))
    ra, rb = ra + [0] * (n - len(ra)), rb + [0] * (n - len(rb))
    if ra != rb:
        return -1 if ra < rb else 1
    none = (1, 0, "")  # "no suffix": above a pre-release, below a number or post-release tag
    for i in range(max(len(sa), len(sb))):
        x = sa[i] if i < len(sa) else none
        y = sb[i] if i < len(sb) else none
        if x != y:
            return -1 if x < y else 1
    return 0


version_sort_key = functools.cmp_to_key(compare_versions)


def major_of(v: str | None) -> int | None:
    m = re.search(r"\d+", v or "")
    return int(m.group(0)) if m else None


def is_prerelease(v: str) -> bool:
    return any(p[0] == 0 for p in _version_parts(v)[1])


_EXACT_VERSION = re.compile(r"^v?\d+(\.\d+)*([-.+]?[0-9A-Za-z.\-+_]*)?$")
_LOWER_BOUND = re.compile(r"(?:\^|~>|~=|~|>=|===|==|=|\[|^)\s*v?(\d+(?:\.(?:\d+|[xX*]))*(?:[-.][0-9A-Za-z.\-]+)?)")


def classify_declared(spec, ecosystem: str):
    """Classify a declared version spec. Returns (version, confidence, lowest) where confidence is
    exact | range | unknown, version is the exact version or the spec as written, and lowest is the
    lowest version the spec allows (the basis §9 uses for ranges), or None."""
    if spec is None:
        return None, "unknown", None
    s = str(spec).strip()
    if not s or s in ("*", "latest", "any", "x", "X"):
        return (s or None), "unknown", None
    if ecosystem == "PyPI":
        m = re.fullmatch(r"===?\s*([0-9][0-9A-Za-z.\-+!]*)", s)
        if m and "*" not in m.group(1):
            return m.group(1), "exact", m.group(1)
    elif ecosystem == "crates.io":
        m = re.fullmatch(r"=\s*([0-9][0-9A-Za-z.\-+]*)", s)
        if m:
            return m.group(1), "exact", m.group(1)
    elif ecosystem == "RubyGems":
        m = re.fullmatch(r"=?\s*([0-9][0-9A-Za-z.\-]*)", s)
        if m:
            return m.group(1), "exact", m.group(1)
    elif ecosystem in ("Maven", "NuGet"):
        m = re.fullmatch(r"\[\s*([0-9][^,\]\s]*)\s*\]", s)
        if m:
            return m.group(1), "exact", m.group(1)
        if _EXACT_VERSION.match(s) and not re.search(r"[*,()\[\]]", s):
            return s, "exact", s
    elif ecosystem in ("npm", "Packagist", "Pub", "CocoaPods", "SwiftURL", "Go"):
        m = re.fullmatch(r"=?\s*(v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?)", s)
        if m:
            return m.group(1), "exact", m.group(1)
    lowest = lowest_in_range(s)
    return s, "range", lowest


def lowest_in_range(spec: str) -> str | None:
    best = None
    for alt in re.split(r"\|\|?", spec):
        alt = alt.strip()
        if not alt or re.match(r"^\s*(<|<=|!=|\()", alt):
            continue
        m = _LOWER_BOUND.search(alt)
        if not m:
            continue
        v = re.sub(r"\.[xX*]", ".0", m.group(1))
        if best is None or compare_versions(v, best) < 0:
            best = v
    return best


# --------------------------------------------------------------------------- severity, CVSS

def severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def _cvss_roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score from a vector string, or None if it can't be parsed."""
    try:
        if not vector.startswith("CVSS:3"):
            return None
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope = m["S"]
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        pr = {"N": 0.85, "L": 0.62 if scope == "U" else 0.68, "H": 0.27 if scope == "U" else 0.5}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        c, i, a = ({"H": 0.56, "L": 0.22, "N": 0.0}[m[k]] for k in ("C", "I", "A"))
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _cvss_roundup(min(impact + exploitability, 10))
    return _cvss_roundup(min(1.08 * (impact + exploitability), 10))


# --------------------------------------------------------------------------- credentials

_USERINFO = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*://)[^/@\s\"'<>]+@")
_SECRET_ASSIGN = re.compile(r"(?i)(_authToken|_auth|_password|password|passwd|token|apikey|api_key|ClearTextPassword)(\s*[=:]\s*|\s*\"?\s*value=\"|\"\s*:\s*\")([^\s\"'<>]+)")
TOKEN_PATTERNS = [
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\boy2[a-z0-9]{43}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]


def redact_token(value) -> str:
    """Show a credential the way the spec allows: the first 4 characters, an ellipsis and the length."""
    v = str(value or "")
    return "%s…(%d)" % (v[:4], len(v)) if v else ""


def strip_userinfo(url: str) -> str:
    return _USERINFO.sub(lambda m: m.group("scheme"), url or "")


def redact_text(text: str) -> str:
    """Remove URL user-info and shorten credential values and well-known token formats in free text."""
    text = strip_userinfo(text)
    text = _SECRET_ASSIGN.sub(lambda m: m.group(1) + m.group(2) + redact_token(m.group(3)), text)
    for pat in TOKEN_PATTERNS:
        text = pat.sub(lambda m: redact_token(m.group(0)), text)
    return text


# --------------------------------------------------------------------------- project walk

DEFAULT_EXCLUDED_DIRS = ["node_modules", "vendor", ".venv", "venv", "dist", "build", "target", ".git",
                         "__pycache__", ".next", ".nuxt", ".svelte-kit", ".turbo", "coverage", ".gradle",
                         ".idea", ".vs", "bin", "obj", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
                         ".ruff_cache", "bower_components", "Pods", ".dart_tool", ".terraform", "site-packages",
                         ".cache", ".yarn", ".pnpm-store", "dependency-audit-out"]
PACKAGE_MANAGER_VENDOR_SIBLINGS = ("composer.json", "Gemfile", "go.mod")
# <static root>/<lib dir> (wwwroot/lib, static/plugins, public/libs ...) holds copied client-side
# libraries, like a plain vendor/ directory: read for vendored JS/CSS only.
STATIC_ROOT_DIRS = {"wwwroot", "static", "public", "assets"}
STATIC_LIB_DIRS = {"lib", "libs", "vendors", "plugins", "third-party", "third_party", "thirdparty"}
# Inside a vendored library these hold the files the page loads (jquery/dist/jquery.min.js), not build output.
VENDORED_KEEP_DIRS = {"dist", "build"}


def gitignore_dirs(root: Path) -> list[str]:
    """Simple directory names from the root .gitignore (no globs, no negations), used as an extra hint."""
    p = root / ".gitignore"
    if not p.is_file():
        return []
    out = []
    for line in read_text(p, limit=200_000).splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")) or any(c in line for c in "*?[]"):
            continue
        name = line.strip("/")
        if "/" in name or not name:
            continue
        if (root / name).is_dir():
            out.append(name)
    return out


def walk_project(root: Path, extra_excludes=(), max_files: int = 300_000):
    """Walk the project. Returns (files, excluded) where files is a list of (relative posix path,
    js_vendor_only) and excluded is the sorted list of skipped directory paths (with a trailing /).
    js_vendor_only is False, or the relative path of the vendored-library directory the file is under.
    A vendor/ directory next to composer.json, a Gemfile or go.mod is package-manager output and is
    skipped; any other vendor/ directory (for example static/vendor/) and a library directory of a
    static web root (wwwroot/lib/) are read for vendored JS/CSS only, dist/ and build/ included."""
    excludes = set(DEFAULT_EXCLUDED_DIRS) | set(extra_excludes)
    files, excluded = [], set()
    root = root.resolve()
    stack = [(root, False)]
    while stack:
        d, vendor_only = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            rel = posix(os.path.relpath(e.path, root))
            if is_dir:
                if e.name == "vendor" and not any((Path(d) / s).exists() for s in PACKAGE_MANAGER_VENDOR_SIBLINGS) \
                        and not (Path(e.path) / "modules.txt").exists() and not (Path(e.path) / "autoload.php").exists():
                    stack.append((Path(e.path), vendor_only or rel))
                    continue
                if not vendor_only and e.name.lower() in STATIC_LIB_DIRS and Path(d).name.lower() in STATIC_ROOT_DIRS:
                    stack.append((Path(e.path), rel))
                    continue
                if (e.name in excludes and not (vendor_only and e.name in VENDORED_KEEP_DIRS)) or e.name.endswith(".egg-info"):
                    excluded.add(rel + "/")
                    continue
                stack.append((Path(e.path), vendor_only))
            elif e.is_file(follow_symlinks=False):
                files.append((rel, vendor_only))
                if len(files) >= max_files:
                    return files, sorted(excluded)
    return files, sorted(excluded)


# --------------------------------------------------------------------------- prompt-injection leads

INJECTION_PATTERNS = [
    (re.compile(r"(?i)\b(ignore|disregard|forget|override)\b[^\n]{0,40}\b(previous|prior|above|earlier|all|any|your)\b[^\n]{0,30}\b(instructions?|rules?|prompts?|guidelines?)\b"), "tries to override the agent's instructions"),
    (re.compile(r"(?i)\b(report|say|state|claim|output|return|respond)\b[^\n]{0,30}\b(no|zero|0)\b[^\n]{0,20}\b(issues?|vulnerabilit(?:y|ies)|findings?|problems?|risks?|cves?)\b"), "asks for a clean report"),
    (re.compile(r"(?i)\b(do not|don't|never|must not|should not)\b[^\n]{0,20}\b(report|flag|mention|scan|audit|list)\b[^\n]{0,30}\b(this|these|it|vulnerabilit|issue|finding|package|file)"), "asks for findings to be hidden"),
    (re.compile(r"(?i)\b(AI|LLM|assistant|agent|Claude|ChatGPT|GPT|Copilot|Gemini|language model|scanner)s?\b\s*[:,]\s*(please\s+)?(ignore|report|mark|treat|skip|do not|don't|you must|you should|always|never)\b"), "addresses an AI agent directly"),
    (re.compile(r"(?i)\b(you are now|new instructions|system prompt|developer message|jailbreak)\b"), "attempts role or prompt manipulation"),
    (re.compile(r"(?i)\bmark\b[^\n]{0,30}\bas\s+(safe|clean|secure|verified|a false positive)\b"), "asks for something to be marked safe"),
]


def find_injection_leads(text: str, relpath: str, max_leads: int = 5) -> list[dict]:
    """Lines in a file the audit reads that look like instructions aimed at an AI agent (hard rule 6).
    These are leads for the agent to judge, not findings."""
    leads = []
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        if len(line) > 2000:
            continue
        for pat, why in INJECTION_PATTERNS:
            if pat.search(line):
                start = max(1, n - 2)
                snippet = "\n".join(redact_text(x)[:300] for x in lines[start - 1:min(len(lines), n + 2)])
                leads.append({"file": relpath, "line": n, "snippet_start_line": start, "snippet": snippet, "why": why})
                break
        if len(leads) >= max_leads:
            break
    return leads


# --------------------------------------------------------------------------- misc

def git_info(path: Path):
    """Commit, branch and dirty flag via read-only git commands, or None when not a git work tree."""
    if not shutil.which("git"):
        return None

    def run(*args):
        try:
            r = subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(path), *args],
                               capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return r.stdout.strip() if r.returncode == 0 else None

    commit = run("rev-parse", "--short", "HEAD")
    if not commit:
        return None
    branch = run("rev-parse", "--abbrev-ref", "HEAD")
    status = run("status", "--porcelain", "--untracked-files=no")
    return {"type": "git", "commit": commit, "branch": None if branch in (None, "HEAD") else branch,
            "dirty": bool(status)}


def git_remote_host(path: Path) -> str | None:
    if not shutil.which("git"):
        return None
    try:
        r = subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(path), "remote", "get-url", "origin"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    url = r.stdout.strip() if r.returncode == 0 else ""
    m = re.match(r"^(?:[a-z+]+://)?(?:[^@/]+@)?([^:/]+)", url)
    return m.group(1).lower() if m else None


@functools.lru_cache(maxsize=None)
def go_bin_dir() -> Path | None:
    """Where `go install` puts binaries: GOBIN, else the first GOPATH entry's bin (read-only `go env`)."""
    go = shutil.which("go")
    if not go:
        return None
    try:
        r = subprocess.run([go, "env", "GOBIN", "GOPATH"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = (r.stdout.splitlines() + ["", ""])[:2] if r.returncode == 0 else ["", ""]
    gobin, gopath = lines[0].strip(), lines[1].strip()
    if gobin:
        return Path(gobin)
    return Path(gopath.split(os.pathsep)[0]) / "bin" if gopath else None


def user_bin_dirs(name: str) -> list[Path]:
    """User-level folders that --setup installs into (spec §2 Setup step 3). They may be missing from PATH."""
    dirs = [go_bin_dir(), Path.home() / "go" / "bin"]
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        dirs.append(Path(os.environ["LOCALAPPDATA"]) / "Programs" / name)
    dirs.append(Path.home() / ".local" / "bin")
    return dedupe([d for d in dirs if d])


def find_tool(name: str) -> str | None:
    """shutil.which, then the user-level folders --setup installs into. Symlinks are kept as they are, so
    a Homebrew path stays valid after `brew upgrade`."""
    exe = shutil.which(name)
    if exe:
        return os.path.abspath(exe)
    for d in user_bin_dirs(name):
        for cand in ([d / (name + ".exe"), d / name] if os.name == "nt" else [d / name]):
            if cand.is_file() and os.access(cand, os.X_OK):
                return os.path.abspath(cand)
    return None


def tool_version(cmd: list[str], timeout: int = 30) -> str | None:
    """Run '<tool> --version' (or similar) and pull out the first version-looking token."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z]+)?", (r.stdout or "") + " " + (r.stderr or ""))
    return m.group(0) if m else None


def parse_evidence(ev: str) -> dict:
    """'services/web/Dockerfile:1 (build stage)' -> {'file': 'services/web/Dockerfile', 'line': 1, 'evidence': ...}."""
    m = re.match(r"^(.+?)(?::(\d+))?(?:\s*\(|,|$)", str(ev).strip())
    if not m:
        return {"file": str(ev), "line": None, "evidence": ev}
    return {"file": m.group(1).strip(), "line": int(m.group(2)) if m.group(2) else None, "evidence": ev}


def dedupe(seq):
    seen, out = set(), []
    for x in seq:
        k = json.dumps(x, sort_keys=True) if isinstance(x, (dict, list)) else x
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out
