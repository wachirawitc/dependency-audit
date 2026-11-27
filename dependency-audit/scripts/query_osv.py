#!/usr/bin/env python3
"""Step 4 of the dependency audit: advisory facts from OSV.dev.

Usage:
    python query_osv.py --out <dir>               # the normal call: uses every input below that exists
    python query_osv.py --out <dir> --mcp-text    # only turn raw/osv-mcp-scan.txt into raw/osv-mcp-matches.json
    python query_osv.py --out <dir> --ids         # only confirm scanner leads (Step 4.2)
    python query_osv.py --out <dir> --inventory   # only the querybatch cross-check (Step 4.3)
    add --offline to skip every OSV.dev call (also implied by an offline inventory)

Inputs, all under <out>/raw/:
  inventory.json         from detect_inventory.py (required)
  osv-mcp-scan.txt       the osv-scanner MCP scan result, saved verbatim by the agent (Step 4.1)
  osv-mcp-matches.json   the rows taken from that text. --mcp-text writes it; the agent may correct it, and a
                         matches file newer than the text is used as it is
  osv-cli.json           osv-scanner CLI JSON, from run_scanners.py
  scanner-results.json   other scanners' matches, normalized by run_scanners.py

What it does:
  leads      every (package, version, ID) row from the MCP scan, the CLI and the other scanners is checked
             against OSV.dev: the ID, or one of its aliases, must come back from OSV's own query for that
             package and version, which is OSV's check that the record lists that version as affected. Rows
             that fail are dropped and listed under "unconfirmed" (MCP rows: "MCP match not confirmed by OSV
             record"); the report puts them in scan.errors. A scanner advisory that OSV doesn't have at all
             is kept under "scanner_only" with the scanner's own facts (Step 4.6).
  inventory  every public library with an exact version goes to the querybatch API. A library known only
             by a declared range is queried package-wide and kept when part of the range is affected
             (range_coverage "whole" -> confidence medium, "partial" -> low). The Go standard library is
             queried for each Go runtime.
  records    every record used is saved to raw/osv/<ID>.json. When an advisory's records give no CVSS v3
             vector or published severity, its GHSA and CVE aliases (then BIT) are fetched for one.

Output: raw/advisories.json, one entry per advisory (merged by alias) per package or runtime. Private
packages are never sent anywhere (hard rule 5): only public package names, ecosystems and versions are.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import fnmatch
import json
import re
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

OSV_API = "https://api.osv.dev/v1"
SOURCE_MCP = "osv-scanner-mcp"
SOURCE_CLI = "osv-scanner"
SOURCE_INVENTORY = "osv.dev querybatch"
SOURCE_ORDER = (SOURCE_MCP, SOURCE_CLI, SOURCE_INVENTORY)
GHSA_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
ID_PREFERENCE = ("GHSA-", "GO-", "RUSTSEC-", "PYSEC-", "CVE-")
SEVERITY_ALIAS_ROUNDS = (("GHSA-", "CVE-"), ("BIT-",))
REF_ORDER = {"ADVISORY": 0, "FIX": 1, "REPORT": 2, "WEB": 3, "ARTICLE": 4, "PACKAGE": 5}
MAX_REFERENCES = 8
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}
GO_RUNTIME_PACKAGES = ("stdlib", "toolchain")

# Ecosystem names the osv-scanner vertical output prints as section headers, besides C.OSV_ECOSYSTEMS.
EXTRA_ECOSYSTEMS = {"CocoaPods", "Hex", "CRAN", "Hackage", "Bioconductor", "GitHub Actions", "ConanCenter", "Alpine",
                    "Debian", "Ubuntu", "Rocky Linux", "AlmaLinux", "Red Hat", "SUSE", "openSUSE", "Photon OS",
                    "Wolfi", "Chainguard", "Mageia", "Android", "Linux", "OSS-Fuzz", "Bitnami"}
ECO_BY_FILE = (
    (re.compile(r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|package\.json)$"), "npm"),
    (re.compile(r"(^|/)(requirements[^/]*\.txt|poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock|pylock[^/]*\.toml)$"), "PyPI"),
    (re.compile(r"(^|/)(pom\.xml|[^/]*gradle\.lockfile|verification-metadata\.xml)$"), "Maven"),
    (re.compile(r"(^|/)(go\.mod|go\.sum)$"), "Go"),
    (re.compile(r"(^|/)Cargo\.lock$"), "crates.io"),
    (re.compile(r"(^|/)(Gemfile\.lock|gems\.locked)$"), "RubyGems"),
    (re.compile(r"(^|/)composer\.lock$"), "Packagist"),
    (re.compile(r"(^|/)(packages\.lock\.json|packages\.config|[^/]*\.(cs|vb|fs)proj|[^/]*\.deps\.json)$"), "NuGet"),
    (re.compile(r"(^|/)pubspec\.lock$"), "Pub"),
    (re.compile(r"(^|/)Package\.resolved$"), "SwiftURL"),
    (re.compile(r"(^|/)mix\.lock$"), "Hex"),
)


def norm_name(ecosystem: str | None, name: str | None) -> str:
    name = name or ""
    if ecosystem == "PyPI":
        return C.normalize_pypi(name)
    if ecosystem in ("NuGet", "Packagist"):
        return name.lower()
    return name


def osv_version(ecosystem: str | None, version) -> str:
    """OSV.dev compares Go versions as semver without the "v"; a two-part Go version gets ".0"."""
    v = str(version or "")
    if ecosystem == "Go":
        v = v[1:] if v.startswith("v") else v
        if re.fullmatch(r"\d+\.\d+", v):
            v += ".0"
    return v


def id_rank(vid: str) -> int:
    return next((i for i, p in enumerate(ID_PREFERENCE) if vid.startswith(p)), len(ID_PREFERENCE))


def eco_from_file(path: str | None) -> str | None:
    for rx, eco in ECO_BY_FILE:
        if rx.search(path or ""):
            return eco
    return None


def safe_name(vid: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", vid)


# --------------------------------------------------------------------------- declared ranges

def _nums(v: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", v or "")[:3]]


def _bump(v: str, idx: int) -> str:
    parts = (_nums(v) + [0, 0, 0])[:3]
    idx = max(0, min(idx, 2))
    parts[idx] += 1
    for i in range(idx + 1, 3):
        parts[i] = 0
    return "%d.%d.%d" % tuple(parts)


def _lead_digits(ver: str) -> int:
    """How many leading dotted parts are numbers: '1.2.x' -> 2, '1.2.3' -> 3."""
    n = 0
    for p in ver.split("."):
        if not p.isdigit():
            break
        n += 1
    return n


def _caret_upper(ver: str) -> str:
    lead = _lead_digits(ver)
    n = (_nums(ver) + [0, 0, 0])[:3]
    if n[0] > 0 or lead <= 1:
        return _bump(ver, 0)
    if n[1] > 0 or lead == 2:
        return _bump(ver, 1)
    return _bump(ver, 2)


_INTERVAL = re.compile(r"([\[(])\s*([^,\])]*?)\s*(?:,\s*([^\])]*?)\s*)?([\])])")
_PART = re.compile(r"^(\^|~>|~=|~|<=|<|>=|>|===|==|=|!=)?\s*v?(\d+(?:\.(?:\d+|[xX*]))*)")


def _interval_upper(m) -> str | None:
    lo, hi, close = m.group(2), m.group(3), m.group(4)
    if hi is None:                      # "[1.0]" pins one version
        return _bump(lo, 2) if lo else None
    if not hi:                          # "[1.5,)" has no upper bound
        return None
    return hi if close == ")" else _bump(hi, 2)


def _part_upper(op: str, ver: str, ecosystem: str) -> str | None:
    lead = _lead_digits(ver)
    wild = lead < len(ver.split("."))
    if lead == 0:
        return None
    if op == "^" or (op == "" and ecosystem == "crates.io" and not wild):
        return _caret_upper(ver)
    if op in ("~>", "~=") or (op == "~" and ecosystem in ("RubyGems", "Packagist")):
        return _bump(ver, lead - 2) if lead >= 2 else _bump(ver, 0)        # pessimistic: drop the last part
    if op == "~":
        return _bump(ver, 1) if lead >= 2 else _bump(ver, 0)               # npm, Poetry, Cargo
    if op == "<":
        return ".".join(ver.split(".")[:lead])
    if op == "<=":
        return _bump(ver, lead - 1)
    if op in ("", "=", "==", "==="):
        if op == "" and ecosystem == "NuGet" and not wild:
            return None                                                   # a bare NuGet version means ">="
        return _bump(ver, lead - 1)
    return None                                                           # >, >=, != add no upper bound


def _alt_upper(alt: str, ecosystem: str) -> str | None:
    intervals = list(_INTERVAL.finditer(alt))
    if intervals and not _INTERVAL.sub("", alt).strip(" ,"):              # Maven / NuGet interval notation
        ups = [_interval_upper(m) for m in intervals]
        return None if any(u is None for u in ups) else max(ups, key=C.version_sort_key)
    m = re.fullmatch(r"v?(\d[\w.\-]*)\s+-\s+v?(\d[\w.\-]*)", alt)       # npm hyphen range "1.2.3 - 2.3"
    if m:
        hi = m.group(2)
        lead = _lead_digits(hi)
        return _bump(hi, 2) if lead >= 3 else _bump(hi, max(lead, 1) - 1)
    ups = []
    for part in re.split(r"\s*,\s*|\s+(?=[<>=~^!])", alt):
        pm = _PART.match(part.strip())
        if pm:
            up = _part_upper(pm.group(1) or "", pm.group(2), ecosystem)
            if up:
                ups.append(up)
    return min(ups, key=C.version_sort_key) if ups else None


def declared_upper(spec: str | None, ecosystem: str) -> str | None:
    """Exclusive upper bound of a declared range ('^4.17.0' -> '5.0.0', '>=1.2,<2' -> '2'), or None when
    the range is open-ended or its syntax isn't understood. None makes every advisory that has a fix count
    as covering only part of the range, which is the cautious reading."""
    s = (spec or "").strip()
    if not s:
        return None
    uppers = []
    for alt in re.split(r"\s*\|\|?\s*", s):
        alt = alt.strip()
        if not alt:
            continue
        up = _alt_upper(alt, ecosystem)
        if up is None:
            return None          # one open-ended alternative makes the whole range open-ended
        uppers.append(up)
    return max(uppers, key=C.version_sort_key) if uppers else None


# --------------------------------------------------------------------------- OSV record helpers

def affected_for(affected, ecosystem: str, name: str) -> list[dict]:
    """The `affected` entries of a record that are about one package."""
    target = norm_name(ecosystem, name)
    out = []
    for a in affected or []:
        pkg = a.get("package") or {}
        if str(pkg.get("ecosystem", "")).split(":")[0] == ecosystem and norm_name(ecosystem, pkg.get("name")) == target:
            out.append(a)
    return out


def intervals_of(entries: list[dict]):
    """Affected intervals [(start or None, end or None, kind)] and explicitly listed versions. kind is the
    event that closes the interval: "fixed" or "limit" (end excluded), "last_affected" (end included), or None
    for an interval with no end."""
    intervals, versions = [], []
    for a in entries:
        versions += [str(v) for v in a.get("versions") or []]
        for rng in a.get("ranges") or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            start, open_ = None, False
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    start = None if str(ev["introduced"]) in ("0", "") else str(ev["introduced"])
                    open_ = True
                elif open_:
                    kind = next((k for k in ("fixed", "last_affected", "limit") if k in ev), None)
                    if kind:
                        intervals.append((start, str(ev[kind]), kind))
                        open_ = False
            if open_:
                intervals.append((start, None, None))
    return C.dedupe(intervals), C.dedupe(versions)


def vulnerable_symbols(entries: list[dict]) -> list[str]:
    """Functions an advisory names (Go `imports`, RustSec `affects.functions`), for the reachability step."""
    out = []
    for a in entries:
        es = a.get("ecosystem_specific") or {}
        for imp in es.get("imports") or []:
            syms = imp.get("symbols") or []
            path = imp.get("path") or ""
            out.append("%s: %s" % (path, ", ".join(syms)) if syms else path)
        out += [str(f) for f in ((es.get("affects") or {}).get("functions") or [])]
    return C.dedupe([s for s in out if s])[:20]


def range_coverage(intervals, versions, lower: str, upper: str | None) -> str | None:
    """'whole' when the affected intervals cover all of [lower, upper), 'partial' when they cover part of
    it, None when no affected version falls inside it."""
    def overlaps(iv):
        start, end, kind = iv
        if upper is not None and start is not None and C.compare_versions(start, upper) >= 0:
            return False
        if end is not None:
            c = C.compare_versions(end, lower)
            if c < 0 or (c == 0 and kind != "last_affected"):
                return False
        return True

    hit = [iv for iv in intervals if overlaps(iv)]
    listed = [v for v in versions
              if C.compare_versions(v, lower) >= 0 and (upper is None or C.compare_versions(v, upper) < 0)]
    if not hit and not listed:
        return None
    cur, progressed = lower, True
    while progressed:
        progressed = False
        for start, end, _kind in hit:
            if start is None or C.compare_versions(start, cur) <= 0:
                if end is None:
                    return "whole"
                if C.compare_versions(end, cur) > 0:
                    cur, progressed = end, True
        if upper is not None and C.compare_versions(cur, upper) >= 0:
            return "whole"
    return "partial"


def describe_range(intervals, versions) -> str | None:
    parts = []
    for start, end, kind in sorted(intervals, key=lambda iv: C.version_sort_key(iv[0] or "0")):
        lo = ">=%s" % start if start else ""
        hi = (("<=%s" if kind == "last_affected" else "<%s") % end) if end else ""
        parts.append(" ".join(x for x in (lo, hi) if x) or "all versions")
    if not parts and versions:
        more = " and %d more" % (len(versions) - 5) if len(versions) > 5 else ""
        return "versions " + ", ".join(versions[:5]) + more
    if len(parts) > 6:
        parts = parts[:6] + ["%d more ranges" % (len(parts) - 6)]
    return " || ".join(parts) or None


def cvss_v3(rec: dict):
    for sev in rec.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            vec = sev.get("score") or ""
            score = C.cvss3_base_score(vec)
            if score is not None:
                m = re.match(r"CVSS:(3\.[01])/", vec)
                return {"version": m.group(1) if m else "3.1", "score": score, "vector": vec}
    return None


def cvss_v4(rec: dict):
    for sev in rec.get("severity") or []:
        if sev.get("type") == "CVSS_V4" and sev.get("score"):
            return {"version": "4.0", "score": None, "vector": sev["score"]}
    return None


def published_severity(rec: dict) -> str | None:
    s = (rec.get("database_specific") or {}).get("severity")
    return GHSA_SEVERITY.get(s.upper()) if isinstance(s, str) else None


def alias_groups(ids: list[str], records: dict) -> list[list[str]]:
    """Split record IDs into groups that are the same advisory (linked by `aliases`)."""
    parent: dict[str, str] = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for vid in ids:
        find(vid)
        for alias in (records.get(vid) or {}).get("aliases") or []:
            ra, rb = find(vid), find(alias)
            if ra != rb:
                parent[rb] = ra
    groups: dict[str, list[str]] = {}
    for vid in ids:
        groups.setdefault(find(vid), []).append(vid)
    return list(groups.values())


parse_evidence = C.parse_evidence


# --------------------------------------------------------------------------- scanner output

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_SCANNED = re.compile(r"^Scanned (.+?) file(?: as an? \S+)? and found (\d+) packages?\b")
_SOURCE = re.compile(r"^(.+?): found (\d+) packages? with issues\s*$")
_PACKAGE = re.compile(r"^(\S+)@(\S*)(?: \(binary packages?: [^)]*\))? has the following (.*?)\s*vulnerabilit")
_VULN = re.compile(r"^ {4}([A-Za-z][A-Za-z0-9]*-[A-Za-z0-9][A-Za-z0-9\-_:.]*):(?:\s|$)")
_SOURCE_TYPE = re.compile(r"^(?:lockfile|sbom|git|docker|artifact|project|image|os|unknown):", re.I)
_TOTAL = re.compile(r"^\s*Total (\d+) packages? affected by (\d+) known vulnerabilit", re.M)


def mcp_text_totals(text: str):
    """The totals line the MCP scan text starts with, as a check on the parse: {"packages", "vulnerabilities"}."""
    m = _TOTAL.search(_ANSI.sub("", unwrap_mcp_text(text)))
    return {"packages": int(m.group(1)), "vulnerabilities": int(m.group(2))} if m else None


def mcp_parse_warning(data: dict):
    """A warning when fewer IDs were read from the MCP text than its totals line counts (rows were missed).
    More is fine: a package listed under two files is counted once in the totals."""
    totals = data.get("totals")
    if not totals:
        return None
    rows = (data.get("rows") or []) + (data.get("dropped_excluded") or [])
    n_ids = sum(len(r.get("ids") or []) for r in rows)
    if n_ids >= totals["vulnerabilities"]:
        return None
    return ("the osv-scanner MCP scan text counts %d known vulnerabilities on %d packages, but only %d IDs on %d rows were "
            "read from it; compare raw/osv-mcp-matches.json with raw/osv-mcp-scan.txt and add the missing rows"
            % (totals["vulnerabilities"], totals["packages"], n_ids, len(rows)))


def rel_to_target(path: str, target) -> str:
    """A scanner's path relative to the project. `target` is one root or a list of roots: the staged
    raw/scan-input/ copy the scanners read (hard rule 0) and the project itself."""
    p = (path or "").strip().replace("\\", "/")
    for t in ([target] if isinstance(target, str) else list(target or [])):
        t = (t or "").replace("\\", "/").rstrip("/")
        if t and p.lower() == t.lower():
            return "."
        if t and p.lower().startswith(t.lower() + "/"):
            return p[len(t) + 1:]
    return p[2:] if p.startswith("./") else p


def under_excluded(path: str, excluded) -> bool:
    f = "/" + (path or "").strip("/") + "/"
    return any(e.strip("/") and ("/" + e.strip("/") + "/") in f for e in excluded or [])


def unwrap_mcp_text(text: str) -> str:
    """The agent should save the tool's text verbatim; accept a saved MCP result object too."""
    s = text.lstrip("﻿").strip()
    if s.startswith("{") or s.startswith("["):
        try:
            data = json.loads(s)
        except ValueError:
            return text
        items = data if isinstance(data, list) else (data.get("content") or (data.get("result") or {}).get("content") or [])
        texts = [c.get("text", "") for c in items if isinstance(c, dict) and c.get("type") == "text"]
        if texts:
            return "\n".join(texts)
    return text


def parse_mcp_text(text: str, target: str, excluded):
    """Rows (file, ecosystem, package, version, IDs) from the osv-scanner MCP scan text (its "vertical"
    output), the rows dropped because their file is excluded, the files it lists as scanned, and whether
    it said "No issues found"."""
    text = _ANSI.sub("", unwrap_mcp_text(text))
    rows, scanned = [], []
    cur_file, cur_eco, cur = None, None, None
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s:
            continue
        m = _SCANNED.match(s)
        if m:
            f = rel_to_target(_SOURCE_TYPE.sub("", m.group(1)), target)
            scanned = [x for x in scanned if x["file"] != f] + [{"file": f, "packages": int(m.group(2))}]
            continue
        if s in C.OSV_ECOSYSTEMS or s.split(":")[0] in EXTRA_ECOSYSTEMS:
            cur_eco, cur = s.split(":")[0], None
            continue
        m = _SOURCE.match(s)
        if m:
            cur_file, cur = rel_to_target(_SOURCE_TYPE.sub("", m.group(1)), target), None
            # The MCP text (osv-scanner 2.7) prints no "Scanned ..." lines, only these headers for files
            # with issues; the header's count is packages with issues, not packages read, so leave it out.
            if not any(x["file"] == cur_file for x in scanned):
                scanned.append({"file": cur_file, "packages": None})
            continue
        m = _PACKAGE.match(s)
        if m:
            cur = {"file": cur_file, "ecosystem": cur_eco or eco_from_file(cur_file), "package": m.group(1),
                   "version": m.group(2) or None, "ids": []}
            state = m.group(3).strip().lower()
            if state and state != "known":
                cur["state"] = state
            rows.append(cur)
            continue
        m = _VULN.match(line)
        if m and cur is not None:
            cur["ids"].append(m.group(1))
    kept = [r for r in rows if not under_excluded(r["file"] or "", excluded)]
    dropped = [r for r in rows if under_excluded(r["file"] or "", excluded)]
    no_issues = any(ln.strip() == "No issues found" for ln in text.splitlines())
    return kept, dropped, scanned, no_issues


def parse_cli_json(data: dict, target: str, excluded):
    rows, scanned = [], []
    for res in data.get("results") or []:
        path = rel_to_target((res.get("source") or {}).get("path") or "", target)
        scanned.append({"file": path, "packages": len(res.get("packages") or [])})
        if under_excluded(path, excluded):
            continue
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            ids = [v.get("id") for v in p.get("vulnerabilities") or [] if v.get("id")]
            if ids:
                rows.append({"file": path, "ecosystem": pkg.get("ecosystem"), "package": pkg.get("name"),
                             "version": pkg.get("version") or None, "ids": ids})
    return rows, scanned


class PrivateNames:
    """Is a package name private? Used for scanner leads, which may name packages the inventory doesn't
    have: the same npm scope, Maven groupId, NuGet prefix or Go host as a private package, or an
    --internal pattern."""

    def __init__(self, inventory: dict):
        self.exact, self.prefixes = set(), set()
        self.patterns = (inventory.get("options") or {}).get("internal_patterns") or []
        for lib in inventory.get("libraries") or []:
            if not lib.get("private"):
                continue
            eco, name = lib["ecosystem"], lib["name"]
            self.exact.add((eco, norm_name(eco, name)))
            if eco == "npm" and name.startswith("@") and "/" in name:
                self.prefixes.add((eco, name.split("/")[0].lower() + "/"))
            elif eco == "Maven" and ":" in name:
                self.prefixes.add((eco, name.split(":")[0].lower() + ":"))
            elif eco == "NuGet" and "." in name:
                self.prefixes.add((eco, name.split(".")[0].lower() + "."))
            elif eco == "Go" and "/" in name:
                self.prefixes.add((eco, name.split("/")[0].lower() + "/"))

    def __call__(self, ecosystem: str, name: str) -> bool:
        n = norm_name(ecosystem, name)
        if (ecosystem, n) in self.exact:
            return True
        if any(e == ecosystem and n.lower().startswith(p) for e, p in self.prefixes):
            return True
        return any(fnmatch.fnmatchcase(name, pat) for pat in self.patterns)


# --------------------------------------------------------------------------- the query

class OsvQuery:
    def __init__(self, out: Path, inventory: dict):
        self.raw = C.raw_dir(out)
        self.inv = inventory
        tgt = inventory.get("target") or {}
        self.target = [p for p in (tgt.get("scan_path"), tgt.get("path")) if p]
        self.excluded = (inventory.get("scope") or {}).get("excluded_paths") or []
        self.records: dict[str, dict | None] = {}
        self.lock = threading.Lock()
        self.errors: list[str] = []
        self.gaps: list[str] = []
        self.unconfirmed: list[dict] = []
        self.scanner_only: list[dict] = []
        self.leads: list[dict] = []
        self.hits: dict[tuple, dict] = {}        # (item id, record id) -> {"item", "sources", "coverage", "upper"}
        self.extra: dict[str, dict] = {}         # purl -> library that only a scanner found
        self.coverage_files: dict[str, list] = {}
        self.mcp_data: dict | None = None
        self.inputs: list[str] = []
        self.stats = {"inventory_queries": 0, "exact": 0, "range": 0, "go_stdlib": 0, "skipped_private": 0,
                      "skipped_no_version": 0, "skipped_ecosystem": 0, "lead_ids": 0, "lead_ids_confirmed": 0}
        self.libs_by_key: dict[tuple, list] = {}
        self.libs_by_id: dict[str, list] = {}
        for lib in inventory.get("libraries") or []:
            self.libs_by_key.setdefault((lib["ecosystem"], norm_name(lib["ecosystem"], lib["name"])), []).append(lib)
            self.libs_by_id.setdefault(lib["id"], []).append(lib)
        self.go_runtimes = [r for r in inventory.get("runtimes") or []
                            if str(r.get("id", "")).startswith("runtime:go@") and r.get("version")]
        self.is_private = PrivateNames(inventory)
        self.lockfiles = {m["path"] for m in inventory.get("manifests") or [] if m.get("kind") == "lockfile"}

    # ---------------------------------------------------------------- OSV calls
    def querybatch(self, queries: list[dict]) -> list[list[str]]:
        """IDs per query, following next_page_token; at most 1000 queries per request."""
        results: list[list[str]] = [[] for _ in queries]
        pending, tokens = list(range(len(queries))), {}
        guard = len(queries) // 1000 + 50
        while pending and guard > 0:
            guard -= 1
            chunk, rest = pending[:1000], pending[1000:]
            body = []
            for i in chunk:
                q = dict(queries[i])
                if i in tokens:
                    q["page_token"] = tokens[i]
                body.append(q)
            res = C.post_json(OSV_API + "/querybatch", {"queries": body}, timeout=90)
            more = []
            for i, r in zip(chunk, res.get("results") or []):
                results[i] += [v["id"] for v in r.get("vulns") or [] if v.get("id")]
                if r.get("next_page_token"):
                    tokens[i] = r["next_page_token"]
                    more.append(i)
            pending = more + rest
        return [C.dedupe(r) for r in results]

    def fetch(self, ids) -> None:
        todo = [i for i in C.dedupe(ids) if i and i not in self.records]
        if not todo:
            return
        osv_dir = self.raw / "osv"
        osv_dir.mkdir(parents=True, exist_ok=True)

        def one(vid):
            try:
                rec = C.get_json("%s/vulns/%s" % (OSV_API, vid), timeout=30)
            except C.FetchError as e:
                with self.lock:
                    self.records[vid] = None
                    if e.status != 404:
                        self.errors.append("OSV record %s could not be fetched (%s)" % (vid, e.message))
                return
            C.write_json(osv_dir / ("%s.json" % safe_name(vid)), rec)
            with self.lock:
                self.records[vid] = rec

        with cf.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(one, todo))

    # ---------------------------------------------------------------- Step 4.3: the inventory
    def inventory_queries(self):
        queries, owners, index = [], [], {}

        def add(query, owner):
            key = json.dumps(query, sort_keys=True)
            if key not in index:
                index[key] = len(queries)
                queries.append(query)
                owners.append([])
            owners[index[key]].append(owner)

        for lib in self.inv.get("libraries") or []:
            eco = lib["ecosystem"]
            if lib.get("private"):
                self.stats["skipped_private"] += 1
            elif eco not in C.OSV_ECOSYSTEMS:
                self.stats["skipped_ecosystem"] += 1
            elif lib.get("version_confidence") == "exact" and lib.get("version"):
                add({"package": {"name": lib["name"], "ecosystem": eco}, "version": osv_version(eco, lib["version"])},
                    (lib, "exact"))
                self.stats["exact"] += 1
            elif lib.get("version_confidence") == "range" and lib.get("lowest_version"):
                add({"package": {"name": lib["name"], "ecosystem": eco}}, (lib, "range"))
                self.stats["range"] += 1
            else:
                self.stats["skipped_no_version"] += 1
        for rt in self.go_runtimes:
            mode = "runtime-exact" if rt.get("version_confidence") == "exact" else "runtime-range"
            add({"package": {"name": "stdlib", "ecosystem": "Go"}, "version": osv_version("Go", rt["version"])}, (rt, mode))
            self.stats["go_stdlib"] += 1
            if mode == "runtime-range":
                self.gaps.append("Go %s is known only as a release line, so the Go standard library was checked at %s; "
                                 "advisories fixed later in that line have confidence low"
                                 % (rt["version"], osv_version("Go", rt["version"])))
        return queries, owners

    def run_inventory(self) -> None:
        queries, owners = self.inventory_queries()
        self.stats["inventory_queries"] = len(queries)
        if not queries:
            return
        try:
            results = self.querybatch(queries)
        except C.FetchError as e:
            self.errors.append("OSV.dev querybatch failed (%s); the cross-check over the inventory did not run" % e.message)
            return
        self.fetch([i for r in results for i in r])
        for ids, own in zip(results, owners):
            for item, mode in own:
                for vid in ids:
                    rec = self.records.get(vid)
                    if not rec or rec.get("withdrawn"):
                        continue
                    if mode in ("exact", "runtime-exact"):
                        self.add_hit(item, vid, SOURCE_INVENTORY)
                        continue
                    if mode == "runtime-range":
                        eco, names, lower = "Go", GO_RUNTIME_PACKAGES, osv_version("Go", item["version"])
                        n = _nums(lower)
                        upper = "%d.%d.0" % (n[0], n[1] + 1) if len(n) >= 2 else None
                    else:
                        eco, names = item["ecosystem"], (item["name"],)
                        lower = osv_version(eco, item["lowest_version"])
                        upper = declared_upper(item.get("declared"), eco)
                    entries = [a for nm in names for a in affected_for(rec.get("affected"), eco, nm)]
                    cov = range_coverage(*intervals_of(entries), lower, upper)
                    if cov:
                        self.add_hit(item, vid, SOURCE_INVENTORY, cov, upper)

    def add_hit(self, item: dict, vid: str, source: str, coverage: str | None = None, upper: str | None = None) -> None:
        key = (item["id"], vid)
        with self.lock:
            h = self.hits.get(key)
            if h is None:
                self.hits[key] = {"item": item, "sources": {source}, "coverage": coverage, "upper": upper}
                return
            h["sources"].add(source)
            if coverage is None or h["coverage"] is None:
                h["coverage"] = None          # an exact match outranks a judgement over a declared range
            elif coverage == "whole":
                h["coverage"] = "whole"

    # ---------------------------------------------------------------- Step 4.2: scanner leads
    def mcp_matches(self, reparse: bool = False):
        txt, js = self.raw / "osv-mcp-scan.txt", self.raw / "osv-mcp-matches.json"
        if txt.is_file() and (reparse or not js.is_file() or js.stat().st_mtime < txt.stat().st_mtime):
            text = C.read_text(txt)
            rows, dropped, scanned, clean = parse_mcp_text(text, self.target, self.excluded)
            C.write_json(js, {"source": "raw/osv-mcp-scan.txt", "rows": rows, "dropped_excluded": dropped,
                              "scanned": scanned, "no_issues": clean, "totals": mcp_text_totals(text)})
        if not js.is_file():
            return None
        data = C.read_json(js)
        self.coverage_files[SOURCE_MCP] = data.get("scanned") or []
        self.mcp_data = data
        warning = mcp_parse_warning(data)
        if warning and warning not in self.errors:
            self.errors.append(warning)
        return data

    def add_lead(self, row: dict, source: str, aliases: bool = False) -> None:
        """aliases=False: each ID is its own advisory (MCP and CLI rows). aliases=True: the IDs are names of one
        advisory (a scanner match such as composer's PKSA-... with its CVE and GHSA), judged once."""
        ids = C.dedupe([i.strip() for i in row.get("ids") or [] if isinstance(i, str) and i.strip()])
        if not ids or not row.get("package"):
            return
        eco = row.get("ecosystem") or eco_from_file(row.get("file"))
        lead = {"source": source, "file": row.get("file"), "ecosystem": eco, "package": row["package"],
                "version": row.get("version") or None, "ids": ids, "aliases": aliases}
        if row.get("facts"):
            lead["scanner_facts"] = row["facts"]
        if not lead["version"]:
            # npm audit and similar name a package without its version: use the inventory's exact versions
            versions = C.dedupe([lib["version"] for lib in self.libs_by_key.get((eco, norm_name(eco, row["package"]))) or []
                                 if lib.get("version_confidence") == "exact" and lib.get("version")])
            for v in versions:
                self.leads.append(dict(lead, version=v, version_from_inventory=True))
            if versions:
                return
        self.leads.append(lead)

    def load_leads(self, reparse_mcp: bool = False) -> None:
        mcp = self.mcp_matches(reparse=reparse_mcp)
        if mcp is not None:
            self.inputs.append("raw/osv-mcp-matches.json")
            for r in mcp.get("rows") or []:
                self.add_lead(r, SOURCE_MCP)
        cli = self.raw / "osv-cli.json"
        if cli.is_file():
            try:
                rows, scanned = parse_cli_json(C.read_json(cli), self.target, self.excluded)
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                self.errors.append("raw/osv-cli.json could not be read (%s)" % e)
            else:
                self.inputs.append("raw/osv-cli.json")
                self.coverage_files[SOURCE_CLI] = scanned
                for r in rows:
                    self.add_lead(r, SOURCE_CLI)
        sr = self.raw / "scanner-results.json"
        if sr.is_file():
            try:
                matches = C.read_json(sr).get("matches") or []
            except (ValueError, AttributeError) as e:
                self.errors.append("raw/scanner-results.json could not be read (%s)" % e)
            else:
                self.inputs.append("raw/scanner-results.json")
                for m in matches:
                    if isinstance(m, dict) and m.get("scanner"):
                        self.add_lead(m, m["scanner"], aliases=True)

    def find_item(self, lead: dict):
        eco, name, version = lead["ecosystem"], lead["package"], lead.get("version") or ""
        if eco == "Go" and name in GO_RUNTIME_PACKAGES:
            if not self.go_runtimes:
                return None
            mm = _nums(osv_version("Go", version))[:2]
            same = [r for r in self.go_runtimes if _nums(osv_version("Go", r["version"]))[:2] == mm]
            return (same or sorted(self.go_runtimes, key=lambda r: C.version_sort_key(r["version"])))[0]
        v = osv_version(eco, version)
        for lib in self.libs_by_key.get((eco, norm_name(eco, name))) or []:
            if lib.get("version_confidence") == "exact" and lib.get("version") \
                    and C.compare_versions(osv_version(eco, lib["version"]), v) == 0:
                return lib
        return None

    def extra_item(self, lead: dict) -> dict:
        """A library that only a scanner found (for example a Maven dependency osv-scanner resolved through
        deps.dev). build_report.py adds it to the inventory with support status unknown."""
        purl = C.make_purl(lead["ecosystem"], lead["package"], lead["version"])
        if purl not in self.extra:
            f = lead.get("file") or None
            self.extra[purl] = {
                "id": purl, "name": lead["package"], "ecosystem": lead["ecosystem"], "version": lead["version"],
                "version_confidence": "exact", "direct": False, "scope": "runtime", "license": None,
                "manifest": f, "lockfile": None, "introduced_by": [], "declared": None, "lowest_version": None,
                "workspace": (f.rsplit("/", 1)[0] if f and "/" in f else "."), "private": None, "mirror": None,
                "vendored": False, "line": None, "found_by": [], "synthetic": True,
                # Found in a file that isn't a lockfile (requirements.txt, pom.xml): the scanner resolved the
                # version itself (osv-scanner asks deps.dev), so the installed version may differ.
                "scanner_resolved": bool(f) and f not in self.lockfiles,
                "lookup_note": "Found by %s in %s; not among the packages read from the manifests and lockfiles"
                               % (lead["source"], f or "the scanned files"),
            }
        if lead["source"] not in self.extra[purl]["found_by"]:
            self.extra[purl]["found_by"].append(lead["source"])
        return self.extra[purl]

    def run_leads(self) -> None:
        self.stats["lead_ids"] = sum(1 if lead["aliases"] else len(lead["ids"]) for lead in self.leads)
        if not self.leads:
            return
        keys: dict[tuple, None] = {}
        for lead in self.leads:
            eco = lead["ecosystem"]
            if not eco:
                lead["_skip"] = "ecosystem could not be determined from %s" % (lead.get("file") or "the row")
            elif self.is_private(eco, lead["package"]):
                lead["_skip"] = "private package; not sent to OSV.dev (hard rule 5)"
            elif eco not in C.OSV_ECOSYSTEMS:
                lead["_skip"] = "%s packages are not part of this audit's inventory" % eco
            elif not lead.get("version"):
                lead["_skip"] = "no version given, and none in the inventory"
            else:
                lead["_key"] = (eco, lead["package"], osv_version(eco, lead["version"]))
                keys.setdefault(lead["_key"], None)
        key_list = list(keys)
        try:
            results = self.querybatch([{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in key_list])
        except C.FetchError as e:
            self.errors.append("OSV.dev could not be queried to confirm scanner matches (%s)" % e.message)
            results = [None] * len(key_list)
        confirmed = dict(zip(key_list, results))
        self.fetch([i for r in results if r for i in r] + [i for lead in self.leads if "_key" in lead for i in lead["ids"]])
        for lead in self.leads:
            if lead["aliases"]:
                self.judge_lead(lead, lead["ids"], confirmed)
            else:
                for vid in lead["ids"]:
                    self.judge_lead(lead, [vid], confirmed)

    def judge_lead(self, lead: dict, ids: list[str], confirmed: dict) -> None:
        """Confirm one advisory (named by ids) for the lead's package and version."""
        source = lead["source"]
        entry = {k: v for k, v in lead.items() if not k.startswith("_") and k not in ("ids", "aliases")}
        entry["id"], entry["ids"] = ids[0], ids
        if "_skip" in lead:
            self.unconfirmed.append(dict(entry, reason=lead["_skip"]))
            return
        returned = confirmed.get(lead["_key"])
        if returned is None:
            self.unconfirmed.append(dict(entry, reason="OSV.dev could not be queried to confirm it"))
            return
        names = set(ids)
        for vid in ids:
            names |= set((self.records.get(vid) or {}).get("aliases") or [])
        match = next((oid for oid in returned
                      if oid in names or names & set((self.records.get(oid) or {}).get("aliases") or [])), None)
        known = [vid for vid in ids if self.records.get(vid) is not None]
        if match is None:
            if not known and source not in (SOURCE_MCP, SOURCE_CLI):
                item = self.find_item(lead) or self.extra_item(lead)
                self.scanner_only.append(dict(entry, affected_package=item["id"]))
                return
            reason = ("MCP match not confirmed by OSV record" if source == SOURCE_MCP
                      else "%s match not confirmed by OSV record" % source)
            if not known:
                reason += " (OSV.dev has no record %s)" % ", ".join(ids)
            self.unconfirmed.append(dict(entry, reason=reason))
            return
        if (self.records.get(match) or {}).get("withdrawn"):
            self.unconfirmed.append(dict(entry, reason="OSV record %s is withdrawn" % match))
            return
        item = self.find_item(lead)
        if item is None and lead["ecosystem"] == "Go" and lead["package"] in GO_RUNTIME_PACKAGES:
            self.unconfirmed.append(dict(entry, reason="no Go runtime in the inventory to attach the standard library to"))
            return
        self.add_hit(item or self.extra_item(lead), match, source)
        self.stats["lead_ids_confirmed"] += 1

    # ---------------------------------------------------------------- Step 4.5: merge
    def records_with_aliases(self, recs):
        out = []
        for a in C.dedupe([x for _vid, r in recs for x in r.get("aliases") or []]):
            if self.records.get(a):
                out.append((a, self.records[a]))
        return out

    @staticmethod
    def severity_known(pool) -> bool:
        return any(cvss_v3(r) or published_severity(r) for _vid, r in pool)

    def fetch_severity_aliases(self, groups) -> None:
        for prefixes in SEVERITY_ALIAS_ROUNDS:
            want = []
            for _item_id, members in groups:
                recs = [(v, self.records.get(v) or {}) for v, _h in members]
                if self.severity_known(recs) or self.severity_known(self.records_with_aliases(recs)):
                    continue
                want += [a for _v, r in recs for a in r.get("aliases") or [] if a.startswith(prefixes)]
            self.fetch(want)

    def merged(self) -> list[dict]:
        by_item: dict[str, list] = {}
        for (item_id, vid), h in self.hits.items():
            by_item.setdefault(item_id, []).append((vid, h))
        groups = []
        for item_id, entries in by_item.items():
            hits = dict(entries)
            for ids in alias_groups([vid for vid, _h in entries], self.records):
                groups.append((item_id, [(vid, hits[vid]) for vid in ids]))
        self.fetch_severity_aliases(groups)
        out = [self.normalize(item_id, members) for item_id, members in groups]
        out.sort(key=lambda a: (C.SEV_RANK.get(a["severity"], 9), CONFIDENCE_RANK[a["confidence"]],
                                a["affected_package"], a["ids"][0]))
        return out

    def severity_for(self, recs):
        """(cvss, severity, source): a CVSS v3 score in the advisory's own records, then their published
        severity, then the same from alias records, else medium until the agent reviews it."""
        aliases = self.records_with_aliases(recs)
        v4 = next((c for c in (cvss_v4(r) for _v, r in recs + aliases) if c), None)
        for pool, via in ((recs, ""), (aliases, " (from alias %s)")):
            for vid, rec in pool:
                c = cvss_v3(rec)
                if c:
                    return c, C.severity_from_score(c["score"]), "CVSS %s base score %.1f%s" % (
                        c["version"], c["score"], via % vid if via else "")
            for vid, rec in pool:
                s = published_severity(rec)
                if s:
                    return v4, s, "Severity %s published in %s" % (rec["database_specific"]["severity"], vid)
        return v4, "medium", "No CVSS v3 score or published severity%s; medium until reviewed" % (
            " (CVSS 4.0 vector only)" if v4 else "")

    def repo_ignore(self, ids, files):
        """The committed osv-scanner.toml entry that ignores this advisory, if any (data, not instructions)."""
        for cfg in self.inv.get("osv_scanner_configs") or []:
            path = cfg.get("path") or ""
            base = path.rsplit("/", 1)[0] if "/" in path else ""
            if base and not any(f and (f == base or f.startswith(base + "/")) for f in files):
                continue
            for ig in cfg.get("ignored") or []:
                if ig.get("id") in ids:
                    return {"file": path, "id": ig["id"], "reason": ig.get("reason"), "ignore_until": ig.get("ignoreUntil")}
        return None

    def locations(self, item: dict) -> list[dict]:
        if str(item["id"]).startswith("runtime:"):
            locs = [parse_evidence(ev) for ev in item.get("evidence") or []]
            return sorted(locs, key=lambda x: 0 if x["file"].endswith("go.mod") else 1)
        libs = self.libs_by_id.get(item["id"]) or [item]
        return [{"file": lib.get("lockfile") or lib.get("manifest"), "manifest": lib.get("manifest"),
                 "line": lib.get("line"), "direct": lib.get("direct"), "scope": lib.get("scope"),
                 "workspace": lib.get("workspace"), "introduced_by": lib.get("introduced_by") or []} for lib in libs]

    def normalize(self, item_id: str, members) -> dict:
        item = members[0][1]["item"]
        runtime = item_id.startswith("runtime:")
        recs = sorted(((v, self.records.get(v) or {}) for v, _h in members), key=lambda x: (id_rank(x[0]), x[0]))
        primary_id, primary = recs[0]
        record_ids = [v for v, _r in recs]
        aliases = {a for _v, r in recs for a in r.get("aliases") or []} - set(record_ids)
        ids = record_ids + sorted(aliases, key=lambda i: (id_rank(i), i))
        eco = "Go" if runtime else item["ecosystem"]
        names = GO_RUNTIME_PACKAGES if runtime else (item["name"],)
        entries = [a for _v, r in recs for nm in names for a in affected_for(r.get("affected"), eco, nm)]
        intervals, versions = intervals_of(entries)
        exact = runtime or item.get("version_confidence") == "exact"
        version = item.get("version") if exact else item.get("lowest_version")
        cur = osv_version(eco, version) if version else None
        all_fixed = sorted({e for _s, e, k in intervals if e and k == "fixed"}, key=C.version_sort_key)
        fixed = [f for f in all_fixed if cur is None or C.compare_versions(f, cur) > 0]
        last_affected = sorted({e for _s, e, k in intervals if e and k == "last_affected"}, key=C.version_sort_key)
        cvss, severity, severity_source = self.severity_for(recs)
        cwe = C.dedupe([c for _v, r in recs for c in (r.get("database_specific") or {}).get("cwe_ids") or []])
        covs = [h["coverage"] for _v, h in members]
        coverage = None if any(c is None for c in covs) else ("whole" if "whole" in covs else "partial")
        confidence = {None: "high", "whole": "medium", "partial": "low"}[coverage]
        if item.get("scanner_resolved") and confidence == "high":
            confidence = "medium"   # Step 5: likely, but the version wasn't read from a lockfile
        sources = set().union(*(h["sources"] for _v, h in members))
        refs = ["https://osv.dev/vulnerability/%s" % primary_id]
        for r in sorted((r for _v, rec in recs for r in rec.get("references") or [] if r.get("url")),
                        key=lambda r: REF_ORDER.get(r.get("type"), 9)):
            if r["url"] not in refs and len(refs) < MAX_REFERENCES:
                refs.append(r["url"])
        locations = self.locations(item)
        # PYSEC and some other records have no summary; a fetched alias record may. Never cut one out of the
        # details: their first line is often the package's own blurb, not the vulnerability.
        summary = primary.get("summary") or next((r.get("summary") for _v, r in recs if r.get("summary")), None) \
            or next((r.get("summary") for _v, r in self.records_with_aliases(recs) if r.get("summary")), None)
        return {
            "affected_package": item_id,
            "runtime": runtime,
            "package": {"name": "stdlib" if runtime else item["name"], "ecosystem": eco,
                        "display_name": "Go standard library" if runtime else item["name"],
                        "version": item.get("version"), "version_confidence": item.get("version_confidence"),
                        "lowest_version": item.get("lowest_version"), "declared": item.get("declared"),
                        "found_only_by_scanner": bool(item.get("synthetic")),
                        "scanner_resolved": bool(item.get("scanner_resolved"))},
            "ids": ids,
            "osv_ids": record_ids,
            "summary": summary,
            "details": (primary.get("details") or "")[:4000],
            "published": primary.get("published"),
            "modified": primary.get("modified"),
            "cvss": cvss,
            "severity": severity,
            "severity_source": severity_source,
            "cwe": cwe,
            "affected_range": describe_range(intervals, versions),
            "fixed_versions": fixed,
            "all_fixed_versions": all_fixed,
            "last_affected": last_affected,
            "fix_available": bool(fixed),
            "range_coverage": coverage,
            "range_upper": members[0][1].get("upper"),
            "confidence": confidence,
            "vulnerable_symbols": vulnerable_symbols(entries),
            "references": refs,
            "detected_by": sorted(sources, key=lambda s: (SOURCE_ORDER.index(s) if s in SOURCE_ORDER else 9, s)),
            "ignored_by_repo_config": self.repo_ignore(set(ids), [loc.get("file") for loc in locations]),
            "locations": locations,
        }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fetch OSV.dev advisory facts for the inventory and scanner leads.")
    ap.add_argument("--out", required=True, help="output directory (holds raw/inventory.json)")
    ap.add_argument("--mcp-text", action="store_true", help="parse raw/osv-mcp-scan.txt into raw/osv-mcp-matches.json")
    ap.add_argument("--ids", action="store_true", help="confirm MCP, CLI and scanner leads against OSV.dev")
    ap.add_argument("--inventory", action="store_true", help="querybatch over the inventory's public libraries")
    ap.add_argument("--offline", action="store_true", help="make no OSV.dev calls")
    args = ap.parse_args(argv)
    out = Path(args.out)
    inv_path = C.raw_dir(out) / "inventory.json"
    if not inv_path.is_file():
        print("error: %s not found; run detect_inventory.py first" % inv_path, file=sys.stderr)
        return 2
    inv = C.read_json(inv_path)
    q = OsvQuery(out, inv)

    if args.mcp_text and not (args.ids or args.inventory):
        data = q.mcp_matches(reparse=True)
        if data is None:
            print("error: %s not found" % (C.raw_dir(out) / "osv-mcp-scan.txt"), file=sys.stderr)
            return 2
        print("wrote %s" % (C.raw_dir(out) / "osv-mcp-matches.json"))
        print("scanned files: %d; rows: %d; dropped (excluded paths): %d%s" % (
            len(data["scanned"]), len(data["rows"]), len(data["dropped_excluded"]),
            "; the scan said \"No issues found\"" if data["no_issues"] else ""))
        for r in data["rows"]:
            print("  %s  %s %s@%s  %s" % (r["file"], r["ecosystem"], r["package"], r["version"], " ".join(r["ids"])))
        if mcp_parse_warning(data):
            print("WARNING: %s" % mcp_parse_warning(data))
        return 0

    run_leads = args.ids or not args.inventory
    run_inv = args.inventory or not args.ids
    offline = args.offline or bool((inv.get("options") or {}).get("offline"))
    if run_leads:
        q.load_leads(reparse_mcp=args.mcp_text)
    if offline:
        C.set_offline(True)
        q.gaps.append("Offline: OSV.dev was not queried, so no advisory could be verified (hard rule 2)")
    else:
        if run_inv:
            q.run_inventory()
        if run_leads:
            q.run_leads()
    advisories = q.merged()

    s = q.stats
    if s["skipped_private"]:
        q.gaps.append("%d private package entr%s not sent to OSV.dev (hard rule 5), so not checked for known vulnerabilities"
                      % (s["skipped_private"], "y was" if s["skipped_private"] == 1 else "ies were"))
    if s["skipped_no_version"]:
        q.gaps.append("%d package entr%s no known version, so not checked for known vulnerabilities"
                      % (s["skipped_no_version"], "y has" if s["skipped_no_version"] == 1 else "ies have"))
    unsupported = sorted({lib["ecosystem"] for lib in inv.get("libraries") or [] if lib["ecosystem"] not in C.OSV_ECOSYSTEMS})
    if unsupported:
        q.gaps.append("OSV.dev has no advisories for %s packages, so they were not checked for known vulnerabilities"
                      % ", ".join(unsupported))
    data = {
        "tool": {"name": "query_osv.py", "version": C.TOOL_VERSION},
        "generated_at": C.now_iso(),
        "mode": "offline" if offline else "online",
        "parts_run": [p for p, ran in (("leads", run_leads), ("inventory", run_inv)) if ran],
        "inputs": q.inputs,
        "stats": dict(s, records_fetched=sum(1 for v in q.records.values() if v)),
        "coverage_files": q.coverage_files,
        "advisories": advisories,
        "extra_libraries": list(q.extra.values()),
        "unconfirmed": q.unconfirmed,
        "scanner_only": q.scanner_only,
        "gaps": C.dedupe(q.gaps),
        "errors": C.dedupe(q.errors),
    }
    C.write_json(C.raw_dir(out) / "advisories.json", data)

    counts: dict[str, int] = {}
    for a in advisories:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1
    print("wrote %s" % (C.raw_dir(out) / "advisories.json"))
    print("advisories: %d (%s) on %d packages or runtimes" % (
        len(advisories), ", ".join("%s %d" % (k, counts[k]) for k in C.SEVERITIES if k in counts) or "none",
        len({a["affected_package"] for a in advisories})))
    print("inventory: %d queries (%d exact, %d declared ranges, %d Go stdlib); skipped %d private, %d without a version, "
          "%d outside OSV" % (s["inventory_queries"], s["exact"], s["range"], s["go_stdlib"], s["skipped_private"],
                               s["skipped_no_version"], s["skipped_ecosystem"]))
    if q.mcp_data is not None:
        m = q.mcp_data
        print("MCP scan text: %d rows with %d IDs read%s" % (
            len(m.get("rows") or []), sum(len(r.get("ids") or []) for r in m.get("rows") or []),
            "; it said \"No issues found\"" if m.get("no_issues") else
            ("; its totals line counts %d" % m["totals"]["vulnerabilities"]) if m.get("totals") else ""))
        if mcp_parse_warning(m):
            print("WARNING: %s" % mcp_parse_warning(m))
    if s["lead_ids"]:
        print("scanner leads: %d IDs, %d confirmed, %d unconfirmed, %d outside OSV" % (
            s["lead_ids"], s["lead_ids_confirmed"], len(q.unconfirmed), len(q.scanner_only)))
    for a in advisories[:30]:
        fix = ("fix " + a["fixed_versions"][0]) if a["fixed_versions"] else "no fix"
        ignored = "  [ignored by %s]" % a["ignored_by_repo_config"]["file"] if a["ignored_by_repo_config"] else ""
        print("  %-8s %-6s %-20s %-40s %s%s" % (a["severity"], a["confidence"], a["ids"][0], a["affected_package"], fix, ignored))
    if len(advisories) > 30:
        print("  ... %d more in advisories.json" % (len(advisories) - 30))
    for x in data["extra_libraries"]:
        print("found only by a scanner: %s (%s)" % (x["id"], x["lookup_note"]))
    for u in q.unconfirmed:
        print("unconfirmed: %s %s@%s %s: %s" % (u["source"], u.get("package"), u.get("version"), u["id"], u["reason"]))
    for g in data["gaps"]:
        print("gap: %s" % g)
    for e in data["errors"]:
        print("error: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
