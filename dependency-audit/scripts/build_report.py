#!/usr/bin/env python3
"""Steps 5 and 6 of the dependency audit: draft the findings for triage, then write dependency-report.json.

Usage:
    python build_report.py draft --out <dir> [--reset-triage]
    python build_report.py build --out <dir> [--severity <min>] [--fail-on <sev>] [--agent-model <id>]

draft  Reads raw/inventory.json, raw/support.json, raw/advisories.json and, when present, raw/scanners.json.
       Turns every fact into a draft finding with an F-ID and writes
         raw/findings-draft.json  the draft findings, triage hints and a review list (read it to triage)
         raw/triage.json          only if it doesn't exist yet: where the agent records its judgment
build  Recomputes the same findings (the ID map in findings-draft.json keeps F-IDs stable), applies
       raw/triage.json and writes <out>/dependency-report.json. Facts always come from raw/: advisory IDs,
       affected ranges, fixed versions, CVSS, CWE, locations, references, detected_by and support data.
       triage.json changes judgment only. Exits 1, without writing the report, when triage.json has errors.

raw/triage.json (every key optional; see references/triage.md):
  summary            {"headline": str|null, "top_actions": [str]|null}; null: written from the final findings
  overrides          {"F-001": {only the fields that change: severity, severity_rationale, confidence,
                      reachability, title, description, remediation}}
  suppress           [{"finding": "F-009", "reason": "Lockfile used only by test fixtures."}]
  extra_findings     [finding]: integrity findings found while reading files; in offline runs also
                      unverified dependency findings, whose advisory.ids must be []
  support_overrides  {"<library or runtime id>": {status, eol_date, reason, source, evidence_file}}, where
                      evidence_file is a page saved under raw/ in this run (for example raw/policies/x.txt)
  notes              [str]: extra entries for scan.errors

Standard library only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import urllib.parse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

DRAFT_NAME = "findings-draft.json"
TRIAGE_NAME = "triage.json"
REPORT_NAME = "dependency-report.json"

CONFIDENCES = ("high", "medium", "low")
CONF_RANK = {c: i for i, c in enumerate(CONFIDENCES)}
CATEGORY_RANK = {"dependency": 0, "support": 1, "integrity": 2}
REACH = ("reachable", "not-reachable", "unknown")
LEVELS = ("low", "medium", "high")
SUPPORT_RULE = {"end-of-life": "support-eol", "deprecated": "support-deprecated", "unmaintained": "support-unmaintained"}
FINDING_SCOPES = {"runtime", "optional"}  # out-of-support dev and build packages stay in the inventory only
JUDGMENT = ("severity", "severity_rationale", "confidence", "reachability", "title", "description", "remediation")
FACTS = ("id", "key", "category", "rule", "status", "cwe", "cvss", "advisory", "affected_package", "location",
         "references", "detected_by")
REPORT_FIELDS = ("id", "category", "rule", "title", "severity", "severity_rationale", "confidence", "status", "cwe",
                 "cvss", "advisory", "affected_package", "location", "reachability", "description", "remediation",
                 "references", "detected_by")
TRIAGE_KEYS = {"_help", "summary", "overrides", "suppress", "extra_findings", "support_overrides", "notes"}
INTEGRITY_SOURCE = "prompt-injection check"
AGENT_SOURCE = "agent review"
SCANNER_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low",
                    "info": "info", "negligible": "info"}
# Scanner skip reasons that cost no coverage, so they are not reported as errors.
HARMLESS_SKIPS = ("the osv-scanner MCP scan ran", "offline run", "--osv-cli never")
OFFLINE_GAP = ("Offline: OSV.dev, endoflife.date and the package registries were not queried, so support status is "
               "unknown and no vulnerability could be verified (hard rule 2)")

EMPTY_TRIAGE = {
    "_help": ("Record triage judgment here, then run build_report.py build. Facts (advisory IDs, versions, CVSS, "
              "locations, support data) come from raw/ and can't be changed here. See references/triage.md."),
    "summary": {"headline": None, "top_actions": None},
    "overrides": {},
    "suppress": [],
    "extra_findings": [],
    "support_overrides": {},
    "notes": [],
}


# --------------------------------------------------------------------------- small helpers

def need(path: Path, made_by: str):
    if not path.is_file():
        raise SystemExit("error: %s not found; run %s first" % (path, made_by))
    try:
        return C.read_json(path)
    except ValueError as e:
        raise SystemExit("error: %s is not valid JSON (%s)" % (path, e))


def optional_json(path: Path):
    if not path.is_file():
        return None
    try:
        return C.read_json(path)
    except ValueError:
        return None


def plural(n: int, one: str, many: str | None = None) -> str:
    return "%d %s" % (n, one if n == 1 else (many or one + "s"))


def join_and(parts) -> str:
    parts = [p for p in parts if p]
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def fid_num(fid) -> int:
    m = re.fullmatch(r"F-(\d+)", str(fid or ""))
    return int(m.group(1)) if m else 10 ** 9


def refs_text(ids, limit: int = 4) -> str:
    ids = sorted(set(ids), key=fid_num)
    if len(ids) <= limit:
        return ", ".join(ids)
    return "%s and %d more" % (", ".join(ids[:limit]), len(ids) - limit)


def raise_one(sev: str) -> str:
    return C.SEVERITIES[max(0, C.SEV_RANK[sev] - 1)]


def quote_text(text, limit: int = 300) -> str:
    """Flatten text that comes from outside the skill (advisories, repository files, registries) into one
    line, with credentials shortened. It is data (hard rule 6); the renderer escapes it."""
    t = C.redact_text(re.sub(r"\s+", " ", str(text or ""))).strip()
    return (t[:limit].rstrip() + "…") if len(t) > limit else t


def plain_text(details: str, limit: int = 700) -> str:
    """The first paragraphs of an advisory's Markdown details as plain text."""
    out, size = [], 0
    for para in re.split(r"\n\s*\n", details or ""):
        lines = [ln for ln in para.strip().splitlines() if not re.match(r"^\s*#{1,6}\s", ln)]
        p = " ".join(ln.strip() for ln in lines).strip()
        if not p or p.startswith(("```", "|", "<")):
            continue
        p = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", p)
        p = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", p)
        p = re.sub(r"(\*\*|__)(.+?)\1", r"\2", p)
        p = re.sub(r"\s+", " ", p).strip()
        if not p:
            continue
        out.append(p)
        size += len(p)
        if size >= limit:
            break
    text = C.redact_text(" ".join(out))
    if len(text) > limit:
        cut = text.rfind(". ", 0, limit)
        text = text[:cut + 1] if cut > limit // 2 else text[:limit].rstrip() + "…"
    return text


def describe(summary, details) -> str:
    text = plain_text(details or "")
    if text:
        return text
    return quote_text(summary, 600) or "See the advisory for details."


def title_text(summary, first_id: str, name: str) -> str:
    s = quote_text(summary, 160)
    return s or "%s in %s" % (first_id, name)


def version_nums(v) -> list[int]:
    core = re.sub(r"^[^\d]*", "", str(v or "")).split("+", 1)[0]
    nums = [int(x) for x in re.findall(r"\d+", core)[:3]]
    return nums + [0] * (3 - len(nums))


def upgrade_risk(current, target, runtime: bool = False) -> tuple[str, str]:
    """(effort, breaking_change_risk) for moving from current to target."""
    if not current or not target:
        return "low", "medium"
    c, t = version_nums(current), version_nums(target)
    if runtime:
        return ("low", "low") if c[:2] == t[:2] else ("medium", "medium")
    if t[0] != c[0] or (c[0] == 0 and t[1] != c[1]):
        return "medium", "high"
    return "low", "low"


def source_names(source) -> list[str]:
    """'endoflife.date API (spring-boot); npm registry' -> ['endoflife.date API', 'npm registry']."""
    out = []
    for part in str(source or "").split(";"):
        name = re.sub(r"\s*\([^)]*\)\s*$", "", part).strip()
        if name:
            out.append(name)
    return C.dedupe(out) or ["support check"]


def registry_url(eco: str, name: str) -> str | None:
    q = urllib.parse.quote
    if eco == "npm":
        return "https://www.npmjs.com/package/%s" % q(name, safe="@/")
    if eco == "PyPI":
        return "https://pypi.org/project/%s/" % q(C.normalize_pypi(name), safe="")
    if eco == "NuGet":
        return "https://www.nuget.org/packages/%s" % q(name, safe="")
    if eco == "Packagist":
        return "https://packagist.org/packages/%s" % q(name.lower(), safe="/")
    if eco == "RubyGems":
        return "https://rubygems.org/gems/%s" % q(name, safe="")
    if eco == "crates.io":
        return "https://crates.io/crates/%s" % q(name, safe="")
    if eco == "Go":
        return "https://pkg.go.dev/%s" % q(name, safe="/")
    if eco == "Pub":
        return "https://pub.dev/packages/%s" % q(name, safe="")
    if eco == "Maven" and ":" in name:
        g, a = name.split(":", 1)
        return "https://central.sonatype.com/artifact/%s/%s" % (q(g, safe=""), q(a, safe=""))
    return None


def unknown_support(reason: str) -> dict:
    return {"status": "unknown", "out_of_support": False, "eol_date": None, "newer_major_available": None,
            "reason": reason, "source": None, "checked_at": C.now_iso()}


def norm_support(s: dict) -> dict:
    status = s.get("status") if s.get("status") in C.SUPPORT_STATUSES else "unknown"
    return {"status": status, "out_of_support": status in C.OUT_OF_SUPPORT, "eol_date": s.get("eol_date"),
            "newer_major_available": s.get("newer_major_available"),
            "reason": s.get("reason") or "No reason was recorded.", "source": s.get("source"),
            "checked_at": s.get("checked_at") or C.now_iso()}


def lib_record(lib: dict, support: dict) -> dict:
    rec = {
        "id": lib["id"], "name": lib["name"], "ecosystem": lib["ecosystem"], "version": lib.get("version"),
        "version_confidence": lib.get("version_confidence") or "unknown", "direct": bool(lib.get("direct")),
        "scope": lib.get("scope") or "runtime", "license": lib.get("license"), "manifest": lib.get("manifest"),
        "lockfile": lib.get("lockfile"), "introduced_by": [str(x) for x in lib.get("introduced_by") or []],
        "support": norm_support(support), "vulnerability_ids": [],
    }
    if lib.get("workspace") and lib["workspace"] != ".":
        rec["workspace"] = lib["workspace"]
    if lib.get("private"):
        rec["private"] = True
    if lib.get("vendored"):
        rec["vendored"] = True
    return rec


def short_name(item: dict) -> str:
    """A readable package name for the headline and actions: the artifact of a Maven group:artifact."""
    name = str(item.get("name") or item.get("id") or "")
    if item.get("ecosystem") == "Maven" and ":" in name:
        return name.split(":", 1)[1]
    return name


def sev_counts(findings) -> dict:
    counts = {s: 0 for s in C.SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def report_order(f):
    return C.SEV_RANK[f["severity"]], CONF_RANK[f["confidence"]], fid_num(f.get("id"))


def check_judgment(k: str, v):
    """None when an override value is acceptable, else what is wrong with it."""
    if k == "severity":
        return None if v in C.SEV_RANK else "must be one of %s" % ", ".join(C.SEVERITIES)
    if k == "confidence":
        return None if v in CONF_RANK else "must be high, medium or low"
    if k in ("severity_rationale", "title", "description"):
        return None if isinstance(v, str) and v.strip() else "must be a non-empty string"
    if k == "reachability":
        if v is None:
            return None
        if not isinstance(v, dict) or v.get("status") not in REACH:
            return 'must be {"status": "reachable" | "not-reachable" | "unknown", "evidence": "..."} or null'
        if set(v) - {"status", "evidence"}:
            return "only status and evidence are allowed"
        if v.get("evidence") is not None and not isinstance(v["evidence"], str):
            return "evidence must be a string"
        return None
    if k == "remediation":
        if not isinstance(v, dict) or not v:
            return "must be an object with summary, effort and/or breaking_change_risk"
        if set(v) - {"summary", "effort", "breaking_change_risk"}:
            return "only summary, effort and breaking_change_risk are allowed"
        if "summary" in v and not (isinstance(v["summary"], str) and v["summary"].strip()):
            return "summary must be a non-empty string"
        for x in ("effort", "breaking_change_risk"):
            if x in v and v[x] not in LEVELS:
                return "%s must be low, medium or high" % x
        return None
    return "unknown field"


def unconfirmed_text(u: dict) -> str:
    reason = str(u.get("reason") or "not confirmed")
    pkg, ver = u.get("package") or "?", u.get("version")
    return "%s%s: %s for %s (%s)" % (reason[0].upper(), reason[1:], u.get("id"), "%s@%s" % (pkg, ver) if ver else pkg,
                                    u.get("source") or "scanner")


# --------------------------------------------------------------------------- builder

class Builder:
    def __init__(self, out: Path):
        self.out = out
        self.raw = C.raw_dir(out)
        self.inv = need(self.raw / "inventory.json", "detect_inventory.py")
        self.sup = need(self.raw / "support.json", "check_support.py")
        self.adv = need(self.raw / "advisories.json", "query_osv.py")
        self.scn = optional_json(self.raw / "scanners.json")
        self.target = Path(self.inv["target"]["path"])
        self.inv_opts = self.inv.get("options") or {}
        self.offline = bool(self.inv_opts.get("offline") or self.adv.get("mode") == "offline"
                            or (self.sup.get("options") or {}).get("offline"))
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.id_map: dict[str, str] = dict((optional_json(self.raw / DRAFT_NAME) or {}).get("id_map") or {})
        self.new_ids: list[str] = []
        self._exists: dict[str, bool] = {}
        self.support_details: dict[str, dict] = {}
        for e in (self.sup.get("runtimes") or []) + (self.sup.get("libraries") or []):
            self.support_details.setdefault(e["id"], e.get("details") or {})
        self.assemble_inventory()

    # ---------------------------------------------------------------- inventory
    def assemble_inventory(self):
        sup_exact, sup_by_id = {}, {}
        for e in self.sup.get("libraries") or []:
            sup_exact.setdefault((e["id"], e.get("manifest")), e.get("support") or {})
            sup_by_id.setdefault(e["id"], e.get("support") or {})
        self.libraries, self.raw_entries = [], {}
        for lib in self.inv.get("libraries") or []:
            s = sup_exact.get((lib["id"], lib.get("manifest"))) or sup_by_id.get(lib["id"])
            self.libraries.append(lib_record(lib, s or unknown_support("The support check did not cover this package.")))
            self.raw_entries.setdefault(lib["id"], []).append(lib)
        for x in self.adv.get("extra_libraries") or []:
            if x["id"] in self.raw_entries:
                continue
            note = str(x.get("lookup_note") or "Found only by a scanner").rstrip(".")
            rec = lib_record(x, unknown_support("%s. Its support status was not checked." % note))
            rec["found_by"] = [str(s) for s in x.get("found_by") or []]
            self.libraries.append(rec)
            self.raw_entries[x["id"]] = [x]
        rt_sup = {e["id"]: e.get("support") or {} for e in self.sup.get("runtimes") or []}
        self.runtimes = []
        for rt in self.inv.get("runtimes") or []:
            self.runtimes.append({
                "id": rt["id"], "name": rt["name"], "version": rt.get("version"),
                "version_confidence": rt.get("version_confidence") or "unknown",
                "evidence": [str(e) for e in rt.get("evidence") or []],
                "support": norm_support(rt_sup.get(rt["id"]) or unknown_support("The support check did not cover this runtime.")),
                "vulnerability_ids": []})
        self.items, self.entries = {}, {}
        for x in self.runtimes + self.libraries:
            self.items.setdefault(x["id"], x)
            self.entries.setdefault(x["id"], []).append(x)
        self.fw_by_lib = {}
        for fw in self.inv.get("frameworks") or []:
            if fw.get("library_id"):
                self.fw_by_lib.setdefault(fw["library_id"], fw)

    def frameworks(self, lib_ids: set) -> list[dict]:
        out = []
        for fw in self.inv.get("frameworks") or []:
            lib_id = fw.get("library_id")
            entries = [e for e in self.entries.get(lib_id) or [] if not str(e["id"]).startswith("runtime:")]
            lib = next((e for e in entries if e.get("manifest") == fw.get("manifest")), entries[0] if entries else None)
            rec = {
                "name": fw["name"], "category": fw.get("category") or "other", "version": fw.get("version"),
                "version_confidence": fw.get("version_confidence") or "unknown", "ecosystem": fw.get("ecosystem"),
                "package": fw.get("package"), "evidence": [str(e) for e in fw.get("evidence") or []],
                "support": dict(lib["support"]) if lib else unknown_support("No package version was found to check."),
                "library_id": lib_id if lib and lib_id in lib_ids else None,
            }
            if fw.get("manifest"):
                rec["manifest"] = fw["manifest"]
            out.append(rec)
        return out

    def exists(self, rel) -> bool:
        if not rel:
            return False
        if rel not in self._exists:
            p = Path(rel)
            self._exists[rel] = not p.is_absolute() and ".." not in p.parts and (self.target / p).is_file()
        return self._exists[rel]

    def location(self, item_id: str, locs=None) -> dict:
        cands = []
        for loc in locs or []:
            f = loc.get("file")
            if f:
                cands.append((f, loc.get("line") if (not loc.get("manifest") or loc.get("manifest") == f) else None))
        item = self.items.get(item_id) or {}
        if str(item_id).startswith("runtime:"):
            for ev in item.get("evidence") or []:
                p = C.parse_evidence(ev)
                cands.append((p["file"], p["line"]))
        else:
            for e in self.raw_entries.get(item_id) or []:
                f = e.get("lockfile") or e.get("manifest")
                if f:
                    cands.append((f, e.get("line") if f == e.get("manifest") else None))
                if e.get("manifest") and e.get("manifest") != f:
                    cands.append((e["manifest"], e.get("line")))
        for f, line in cands:
            if self.exists(f):
                return {"file": f, "line": line, "snippet_start_line": None, "snippet": None}
        f, line = cands[0] if cands else (None, None)
        return {"file": f, "line": line, "snippet_start_line": None, "snippet": None}

    # ---------------------------------------------------------------- support overrides
    def apply_support_overrides(self, overrides):
        if not isinstance(overrides, dict):
            self.errors.append("support_overrides must be an object keyed by library or runtime id")
            return
        raw_root = self.raw.resolve()
        allowed = {"status", "eol_date", "reason", "source", "evidence_file", "newer_major_available"}
        for item_id, ov in overrides.items():
            where = "support_overrides[%s]" % item_id
            targets = self.entries.get(item_id)
            if not targets:
                self.errors.append("%s: no library or runtime with that id in the inventory" % where)
                continue
            if not isinstance(ov, dict):
                self.errors.append("%s: must be an object" % where)
                continue
            if set(ov) - allowed:
                self.errors.append("%s: unknown field(s) %s" % (where, ", ".join(sorted(set(ov) - allowed))))
                continue
            status, reason, eol = ov.get("status"), str(ov.get("reason") or "").strip(), ov.get("eol_date")
            if status not in C.SUPPORT_STATUSES:
                self.errors.append("%s: status must be one of %s" % (where, ", ".join(C.SUPPORT_STATUSES)))
                continue
            if not reason:
                self.errors.append("%s: reason is required" % where)
                continue
            if eol is not None and not (isinstance(eol, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", eol)):
                self.errors.append("%s: eol_date must be YYYY-MM-DD or null" % where)
                continue
            source, checked = ov.get("source"), C.now_iso()
            if status != "unknown" or eol:
                path = None
                for base in (self.out, self.raw):
                    p = (base / str(ov.get("evidence_file") or "")).resolve()
                    if ov.get("evidence_file") and p.is_file():
                        path = p
                        break
                if not source:
                    self.errors.append("%s: source is required for any status but unknown (hard rule 2)" % where)
                    continue
                if path is None or raw_root not in path.parents:
                    self.errors.append("%s: evidence_file must name a page saved under %s in this run, for example "
                                       "raw/policies/<name>.txt (hard rule 2)" % (where, C.posix(self.raw)))
                    continue
                checked = C.iso(dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc))
            for t in targets:
                t["support"] = {"status": status, "out_of_support": status in C.OUT_OF_SUPPORT, "eol_date": eol,
                                "newer_major_available": ov.get("newer_major_available", t["support"].get("newer_major_available")),
                                "reason": quote_text(reason, 600), "source": source or None, "checked_at": checked}

    # ---------------------------------------------------------------- findings from facts
    def compute(self):
        deps = [self.osv_finding(a) for a in self.adv.get("advisories") or []] + self.scanner_findings()
        sup = self.support_findings(deps)
        integ = [self.lead_finding(lead) for lead in self.inv.get("integrity_leads") or []]
        findings = deps + sup + integ
        self.assign_ids(findings)
        dep_by_key = {f["key"]: f for f in deps}
        for f in sup:
            self.finalize_support(f, dep_by_key)
        return findings, dep_by_key

    def assign_ids(self, findings):
        n = max([fid_num(v) for v in self.id_map.values() if fid_num(v) < 10 ** 9] + [0])
        order = sorted(findings, key=lambda f: (C.SEV_RANK[f["severity"]], CATEGORY_RANK[f["category"]],
                                                CONF_RANK[f["confidence"]], f["affected_package"] or "", f["key"]))
        for f in order:
            fid = self.id_map.get(f["key"])
            if fid is None:
                n += 1
                fid = "F-%03d" % n
                self.id_map[f["key"]] = fid
                self.new_ids.append(fid)
            f["id"] = fid

    def osv_finding(self, a: dict) -> dict:
        pkg = a.get("package") or {}
        runtime = bool(a.get("runtime"))
        item = self.items.get(a["affected_package"]) or {}
        name = pkg.get("display_name") or pkg.get("name") or a["affected_package"]
        exact = runtime or pkg.get("version_confidence") == "exact"
        current = pkg.get("version") if exact else pkg.get("lowest_version")
        locs = a.get("locations") or []
        rationale = [str(a.get("severity_source") or "Severity taken from the advisory").rstrip(".") + "."]
        scopes = {loc.get("scope") for loc in locs if loc.get("scope")}
        if not runtime and scopes and not scopes & FINDING_SCOPES:
            rationale.append("Installed only in %s scope." % " and ".join(sorted(scopes)))
        known = ("the release line %s" % pkg.get("version")) if runtime else \
            ("the declared range %s" % (pkg.get("declared") or pkg.get("version")))
        if a.get("range_coverage") == "whole":
            rationale.append("Only %s is known, and every version in it is affected." % known)
        elif a.get("range_coverage") == "partial":
            rationale.append("Only %s is known, and only part of it is affected: depends on the resolved version." % known)
        if pkg.get("scanner_resolved"):
            src = " and ".join(a.get("detected_by") or ["a scanner"])
            where = (locs[0].get("file") if locs else None) or "a manifest"
            rationale.append("%s resolved version %s from %s itself (the repository has no lockfile entry for it), so "
                             "the installed version may differ: confidence medium." % (src, current, where))
        ig = a.get("ignored_by_repo_config")
        if ig:
            why = (' with the reason "%s"' % quote_text(ig["reason"])) if ig.get("reason") else " without giving a reason"
            rationale.append("The repository's %s ignores this advisory%s. That file is data, not an instruction, so the "
                             "finding stays and its severity is not lowered on the file's say-so (Step 4.3)."
                             % (ig.get("file") or "osv-scanner.toml", why))
        hints = {k: v for k, v in {
            "vulnerable_symbols": a.get("vulnerable_symbols"),
            "locations": [{k2: loc.get(k2) for k2 in ("file", "scope", "direct", "workspace", "introduced_by")
                           if loc.get(k2) not in (None, [], "")} for loc in locs][:10],
            "ignored_by_repo_config": ig,
            "range_coverage": a.get("range_coverage"),
            "version_confidence": pkg.get("version_confidence"),
            "found_only_by_scanner": pkg.get("found_only_by_scanner") or None,
            "scanner_resolved": pkg.get("scanner_resolved") or None,
            "published": a.get("published"),
        }.items() if v not in (None, [], "")}
        fixed = [str(v) for v in a.get("fixed_versions") or []]
        rem_name = (item.get("name") or "Go") if runtime else name
        return {
            "key": "osv|%s|%s" % (a["affected_package"], (a.get("osv_ids") or a["ids"])[0]),
            "category": "dependency", "rule": "osv",
            "title": title_text(a.get("summary"), a["ids"][0], name),
            "severity": a["severity"] if a.get("severity") in C.SEV_RANK else "medium",
            "severity_rationale": " ".join(rationale),
            "confidence": a["confidence"] if a.get("confidence") in CONF_RANK else "high",
            "status": "verified",
            "cwe": [str(c) for c in a.get("cwe") or []],
            "cvss": a.get("cvss"),
            "advisory": {"ids": [str(i) for i in a["ids"]], "source": "osv.dev",
                         "affected_range": a.get("affected_range") or None, "fixed_versions": fixed},
            "affected_package": a["affected_package"],
            "location": self.location(a["affected_package"], locs),
            "reachability": None,
            "description": describe(a.get("summary"), a.get("details")),
            "remediation": self.dep_remediation(rem_name, current, fixed, a.get("last_affected") or [], locs, runtime),
            "references": [str(r) for r in a.get("references") or []],
            "detected_by": [str(s) for s in a.get("detected_by") or ["osv.dev querybatch"]],
            "hints": hints,
        }

    def dep_remediation(self, name, current, fixed, last_affected, locs, runtime) -> dict:
        if fixed:
            target = fixed[0]
            if runtime:
                text = "Upgrade %s to %s or later and rebuild." % (name, target)
            else:
                text = "Upgrade %s to %s or later." % (name, target)
                chains = [loc.get("introduced_by") for loc in locs if loc.get("introduced_by")]
                if locs and chains and not any(loc.get("direct") for loc in locs):
                    text += (" It is a transitive dependency (via %s): upgrade the package that pulls it in, or pin it "
                             "with your package manager's override or resolution setting." % " → ".join(chains[0]))
            effort, risk = upgrade_risk(current, target, runtime)
        else:
            text = "No fixed version has been released"
            if last_affected:
                text += " (affected up to and including %s)" % last_affected[-1]
            text += (". Replace %s, or avoid the affected feature until a fix is released; the advisory may describe "
                     "a workaround." % name)
            effort, risk = "medium", "medium"
        files = C.dedupe([loc.get("file") for loc in locs if loc.get("file")]) if not runtime else []
        if len(files) > 1:
            more = files[1:]
            text += " Also installed from %s%s." % (", ".join(more[:3]), " and %d more" % (len(more) - 3) if len(more) > 3 else "")
        return {"summary": text, "effort": effort, "breaking_change_risk": risk}

    def scanner_findings(self) -> list[dict]:
        groups: dict[str, dict] = {}
        for s in self.adv.get("scanner_only") or []:
            key = "scanner|%s|%s" % (s["affected_package"], s["id"])
            g = groups.setdefault(key, {"entry": s, "sources": [], "ids": []})
            g["sources"].append(str(s.get("source") or "scanner"))
            g["ids"] = C.dedupe(g["ids"] + [str(i) for i in s.get("ids") or [s["id"]]])
        out = []
        for key, g in groups.items():
            s, sources = g["entry"], C.dedupe(g["sources"])
            facts = s.get("scanner_facts") or {}
            item = self.items.get(s["affected_package"]) or {}
            name = item.get("name") or s.get("package") or s["affected_package"]
            sev_raw = str(facts.get("severity") or "").strip().lower()
            sev = SCANNER_SEVERITY.get(sev_raw)
            if sev:
                rationale = "Severity \"%s\" as reported by %s; OSV.dev has no record of this advisory." % (sev_raw, sources[0])
            else:
                sev = "medium"
                rationale = "%s gave no severity and OSV.dev has no record of this advisory; medium until reviewed." % sources[0]
            cvss, vec = None, facts.get("cvss")
            if isinstance(vec, str) and vec.startswith("CVSS:3"):
                score = C.cvss3_base_score(vec)
                if score is not None:
                    cvss = {"version": vec[5:8], "score": score, "vector": vec}
            fixed = [str(v) for v in facts.get("fixed_versions") or [] if v] if isinstance(facts.get("fixed_versions"), list) else []
            url = facts.get("url")
            cwe = facts.get("cwe") if isinstance(facts.get("cwe"), list) else []
            rng = quote_text(facts.get("range"), 120) or None
            if fixed:
                rem_text = "Upgrade %s to %s or later." % (name, fixed[0])
                effort, risk = upgrade_risk(item.get("version"), fixed[0])
            else:
                rem_text = "Upgrade %s to a version outside the vulnerable range%s; %s gave no fixed version." % (
                    name, " (%s)" % rng if rng else "", sources[0])
                effort, risk = "low", "medium"
            out.append({
                "key": key, "category": "dependency", "rule": "scanner-advisory",
                "title": quote_text(facts.get("title"), 160) or "%s in %s" % (s["id"], name),
                "severity": sev, "severity_rationale": rationale,
                "confidence": "high" if item.get("version_confidence") == "exact" else "medium",
                "status": "verified",
                "cwe": [c for c in cwe if isinstance(c, str) and re.fullmatch(r"CWE-\d+", c)],
                "cvss": cvss,
                "advisory": {"ids": g["ids"], "source": sources[0], "affected_range": rng, "fixed_versions": fixed},
                "affected_package": s["affected_package"],
                "location": self.location(s["affected_package"], [{"file": s.get("file")}]),
                "reachability": None,
                "description": ("%s Reported by %s; OSV.dev has no record of this advisory, so only the scanner's own "
                                "data is shown." % (quote_text(facts.get("title"), 300).rstrip(".") + "." if facts.get("title") else "",
                                                     join_and(sources))).strip(),
                "remediation": {"summary": rem_text, "effort": effort, "breaking_change_risk": risk},
                "references": [url] if isinstance(url, str) and re.match(r"https?://", url) else [],
                "detected_by": sources,
                "hints": {"scanner_facts": facts} if facts else {},
            })
        return out

    def support_findings(self, deps: list[dict]) -> list[dict]:
        unfixed: dict[str, list[str]] = {}
        for f in deps:
            if f["rule"] == "osv" and not f["advisory"]["fixed_versions"]:
                unfixed.setdefault(f["affected_package"], []).append(f["key"])
        out = []
        for rt in self.runtimes:
            if rt["support"]["out_of_support"]:
                out.append(self.support_finding(rt, "runtime", unfixed.get(rt["id"], [])))
        seen = set()
        for lib in self.libraries:
            if lib["id"] in seen:
                continue
            seen.add(lib["id"])
            hits = [e for e in self.entries[lib["id"]] if e["support"]["out_of_support"] and e["scope"] in FINDING_SCOPES]
            if hits:
                fw = self.fw_by_lib.get(lib["id"])
                out.append(self.support_finding(hits[0], "framework" if fw else "library", unfixed.get(lib["id"], []), fw))
        return out

    def support_finding(self, item: dict, kind: str, unfixed_keys: list[str], fw: dict | None = None) -> dict:
        s, status = item["support"], item["support"]["status"]
        name = fw["name"] if fw else item["name"]
        version = item.get("version") or ""
        if kind == "runtime":
            base, label = "high", "End-of-life runtime" if status == "end-of-life" else "%s runtime" % status.capitalize()
        elif kind == "framework" and status == "end-of-life":
            base, label = "high", "End-of-life framework"
        else:
            base = "medium"
            label = "%s %s" % ("End-of-life" if status == "end-of-life" else status.capitalize(),
                               "framework package" if kind == "framework" else "library")
        title = ("%s %s is %s" % (name, version, status)).replace("  ", " ")
        details = self.support_details.get(item["id"]) or {}
        product = details.get("endoflife_product")
        desc = s["reason"] + (" A newer major version is available." if s.get("newer_major_available") else "")
        if kind == "runtime":
            rem = "Move to a supported %s release line%s." % (item["name"], " (endoflife.date/%s lists them)" % product if product else "")
            effort, risk = "medium", "medium"
        elif status == "deprecated":
            alt = details.get("alternate_package") or {}
            if alt.get("id"):
                rng = alt.get("range")
                rem = "Replace %s with %s%s, the replacement the registry names." % (
                    item["name"], alt["id"], " %s" % rng if rng and rng != "*" else "")
            else:
                rem = "Replace %s with a maintained alternative." % item["name"]
            effort, risk = "medium", "medium"
        elif status == "end-of-life":
            rem = "Upgrade %s to a supported release line%s." % (name, " (endoflife.date/%s lists them)" % product if product else "")
            effort, risk = ("high", "high") if kind == "framework" else ("medium", "medium")
        else:
            rem = "Replace %s with a maintained alternative, or plan to maintain a fork." % item["name"]
            effort, risk = "medium", "medium"
        refs = []
        if product:
            refs.append("https://endoflife.date/%s" % urllib.parse.quote(product, safe=""))
        if kind != "runtime" and not item.get("private"):
            url = registry_url(item.get("ecosystem") or "", item["name"])
            if url:
                refs.append(url)
        pol = details.get("policy") or {}
        if isinstance(pol.get("url"), str) and re.match(r"https?://", pol["url"]):
            refs.append(pol["url"])
        confident = kind == "runtime" or item.get("version_confidence") == "exact"
        return {
            "key": "support|%s" % item["id"], "category": "support", "rule": SUPPORT_RULE[status],
            "title": title, "severity": raise_one(base) if unfixed_keys else base, "severity_rationale": "",
            "confidence": "high" if confident else "medium", "status": "verified", "cwe": ["CWE-1104"], "cvss": None,
            "advisory": None, "affected_package": item["id"], "location": self.location(item["id"]),
            "reachability": None, "description": desc,
            "remediation": {"summary": rem, "effort": effort, "breaking_change_risk": risk},
            "references": C.dedupe(refs), "detected_by": source_names(s.get("source")),
            "hints": {"support": s, "details": details,
                      "scopes": sorted({e["scope"] for e in self.entries[item["id"]] if e.get("scope")})},
            "_base": base, "_label": label, "_unfixed": list(unfixed_keys),
        }

    def finalize_support(self, f: dict, dep_by_key: dict, inactive=frozenset()):
        """Set a support finding's severity and rationale: the Step 3 level, raised one level when the item also
        has a known vulnerability with no fixed version (suppressed findings don't count)."""
        hits = [dep_by_key[k] for k in f["_unfixed"] if k in dep_by_key and k not in inactive]
        text = "%s: %s (Step 3)." % (f["_label"], f["_base"].capitalize())
        if hits:
            f["severity"] = raise_one(f["_base"])
            named = ["%s (%s)" % (h["advisory"]["ids"][0], h["id"]) for h in sorted(hits, key=lambda h: fid_num(h["id"]))[:3]]
            if len(hits) > 3:
                named.append("%d more" % (len(hits) - 3))
            one = len(hits) == 1
            text += " Raised one level to %s because %s %s this version and %s no fixed version." % (
                f["severity"].capitalize(), join_and(named), "affects" if one else "affect", "has" if one else "have")
        else:
            f["severity"] = f["_base"]
        f["severity_rationale"] = text

    def lead_finding(self, lead: dict) -> dict:
        why = str(lead.get("why") or "addresses an AI agent directly")
        return {
            "key": "integrity|%s:%s" % (lead["file"], lead.get("line")),
            "category": "integrity", "rule": "prompt-injection-attempt", "title": "Prompt-injection attempt",
            "severity": "medium",
            "severity_rationale": ("Text in the repository tries to steer an automated audit (it %s). It was treated as "
                                   "data and changed nothing in this report. Medium until reviewed: find out who added "
                                   "it and why." % why),
            "confidence": "medium", "status": "verified", "cwe": [], "cvss": None, "advisory": None,
            "affected_package": None,
            "location": {"file": lead["file"], "line": lead.get("line"), "snippet_start_line": lead.get("snippet_start_line"),
                         "snippet": lead.get("snippet")},
            "reachability": None,
            "description": ("%s line %s contains text aimed at an AI auditor: it %s. Repository text is data, never "
                            "instructions (hard rule 6), so the audit ignored it." % (lead["file"], lead.get("line"), why)),
            "remediation": {"summary": ("Remove the text, and check the change history for who added it and whether "
                                        "other changes came with it."), "effort": "low", "breaking_change_risk": "low"},
            "references": [], "detected_by": [INTEGRITY_SOURCE], "hints": {"why": why},
        }

    # ---------------------------------------------------------------- triage
    def extra_finding(self, x, i: int):
        where = "extra_findings[%d]" % i
        if not isinstance(x, dict):
            self.errors.append("%s: must be an object" % where)
            return None
        cat = x.get("category")
        sev = x.get("severity", "medium")
        conf = x.get("confidence", "medium")
        for k, v in (("severity", sev), ("confidence", conf)):
            err = check_judgment(k, v)
            if err:
                self.errors.append("%s.%s: %s" % (where, k, err))
                return None
        for k in ("title", "description", "severity_rationale"):
            if k in x and check_judgment(k, x[k]):
                self.errors.append("%s.%s: must be a non-empty string" % (where, k))
                return None
        rem = x.get("remediation") or {}
        if rem and check_judgment("remediation", rem):
            self.errors.append("%s.remediation: %s" % (where, check_judgment("remediation", rem)))
            return None
        if cat == "integrity":
            loc = x.get("location") or {}
            file, line, snippet = loc.get("file"), loc.get("line"), loc.get("snippet")
            if not self.exists(file):
                self.errors.append("%s: location.file must be an existing file under the target, relative to it" % where)
                return None
            if line is not None and not (isinstance(line, int) and line > 0):
                self.errors.append("%s: location.line must be a positive integer" % where)
                return None
            if snippet is not None:
                if not isinstance(snippet, str) or len(snippet.split("\n")) > 5:
                    self.errors.append("%s: location.snippet must be text of 5 lines or fewer (hard rule 3)" % where)
                    return None
                snippet = C.redact_text(snippet)
            start = loc.get("snippet_start_line") or (line if snippet else None)
            if x.get("affected_package") is not None:
                self.errors.append("%s: an integrity finding has affected_package null (hard rule 6)" % where)
                return None
            return {
                "key": "integrity|%s:%s" % (file, line), "category": "integrity", "rule": "prompt-injection-attempt",
                "title": x.get("title") or "Prompt-injection attempt", "severity": sev,
                "severity_rationale": x.get("severity_rationale") or "Text in the repository tries to steer an automated audit.",
                "confidence": conf, "status": "verified", "cwe": [], "cvss": None, "advisory": None, "affected_package": None,
                "location": {"file": file, "line": line, "snippet_start_line": start if snippet else None, "snippet": snippet},
                "reachability": None,
                "description": x.get("description") or "%s contains text aimed at an AI auditor; the audit ignored it (hard rule 6)." % file,
                "remediation": dict({"summary": "Remove the text and check who added it.", "effort": "low",
                                     "breaking_change_risk": "low"}, **rem),
                "references": [], "detected_by": [AGENT_SOURCE], "hints": {},
            }
        if cat == "dependency":
            if not self.offline:
                self.errors.append("%s: agent-written dependency findings are allowed only in offline runs; online, every "
                                   "advisory comes from OSV.dev or a scanner (hard rule 2)" % where)
                return None
            if x.get("status") != "unverified":
                self.errors.append("%s: status must be \"unverified\" (hard rule 2)" % where)
                return None
            if (x.get("advisory") or {}).get("ids"):
                self.errors.append("%s: advisory.ids must be []: never write an advisory ID from memory (hard rule 2)" % where)
                return None
            pkg = x.get("affected_package")
            if pkg not in self.items:
                self.errors.append("%s: affected_package must be a library or runtime id from the inventory" % where)
                return None
            if not x.get("title") or not x.get("description"):
                self.errors.append("%s: title and description are required" % where)
                return None
            rationale = (x.get("severity_rationale") or "Suspected from the installed version.").rstrip(".")
            return {
                "key": "extra|dependency|%s|%s" % (pkg, x["title"]), "category": "dependency", "rule": "osv",
                "title": x["title"], "severity": sev,
                "severity_rationale": rationale + ". Not verified: no advisory record could be fetched in this offline run.",
                "confidence": conf, "status": "unverified", "cwe": [], "cvss": None,
                "advisory": {"ids": [], "source": None, "affected_range": None, "fixed_versions": []},
                "affected_package": pkg, "location": self.location(pkg), "reachability": None,
                "description": x["description"],
                "remediation": dict({"summary": "Verify this online (run the audit without --offline) before acting on it.",
                                     "effort": "low", "breaking_change_risk": "low"}, **rem),
                "references": [], "detected_by": [AGENT_SOURCE], "hints": {},
            }
        self.errors.append("%s: category must be \"integrity\" or (offline only) \"dependency\"; support findings come from "
                           "support_overrides" % where)
        return None

    def parse_suppress(self, items, by_id) -> dict:
        out = {}
        if not isinstance(items, list):
            self.errors.append("suppress must be a list of {\"finding\": \"F-…\", \"reason\": \"…\"}")
            return out
        for i, s in enumerate(items):
            where = "suppress[%d]" % i
            if not isinstance(s, dict):
                self.errors.append("%s: must be an object" % where)
                continue
            fid, reason = s.get("finding"), s.get("reason")
            if fid not in by_id:
                self.errors.append("%s: no finding %r (see raw/findings-draft.json)" % (where, fid))
                continue
            if not isinstance(reason, str) or not reason.strip():
                self.errors.append("%s: a reason is required; a finding is never dropped silently (Step 5)" % where)
                continue
            if set(s) - {"finding", "reason"}:
                self.warnings.append("%s: ignored field(s) %s" % (where, ", ".join(sorted(set(s) - {"finding", "reason"}))))
            out[fid] = reason.strip()
        return out

    def apply_overrides(self, overrides, by_id):
        if not isinstance(overrides, dict):
            self.errors.append("overrides must be an object keyed by finding id")
            return
        for fid, ov in overrides.items():
            where = "overrides[%s]" % fid
            f = by_id.get(fid)
            if f is None:
                self.errors.append("%s: no finding with that id (see raw/findings-draft.json)" % where)
                continue
            if not isinstance(ov, dict):
                self.errors.append("%s: must be an object" % where)
                continue
            old = f["severity"]
            for k, v in ov.items():
                if k in FACTS:
                    self.errors.append("%s: '%s' is a fact taken from raw/ and can't be changed in triage; suppress the "
                                       "finding instead if it is wrong" % (where, k))
                    continue
                if k not in JUDGMENT:
                    self.errors.append("%s: unknown field '%s' (allowed: %s)" % (where, k, ", ".join(JUDGMENT)))
                    continue
                err = check_judgment(k, v)
                if err:
                    self.errors.append("%s.%s: %s" % (where, k, err))
                    continue
                if k == "remediation":
                    f["remediation"] = dict(f["remediation"], **{a: (b.strip() if isinstance(b, str) else b) for a, b in v.items()})
                elif k == "reachability":
                    f["reachability"] = None if v is None else {"status": v["status"], "evidence": (v.get("evidence") or "").strip() or None}
                    if v is not None and v["status"] != "unknown" and not (v.get("evidence") or "").strip():
                        self.warnings.append("%s: reachability %s without evidence (Step 4.7 asks for evidence)" % (fid, v["status"]))
                else:
                    f[k] = v.strip() if isinstance(v, str) else v
            if f["severity"] != old and "severity_rationale" not in ov:
                self.warnings.append("%s: severity changed from %s to %s without a severity_rationale; a note was added"
                                     % (fid, old, f["severity"]))
                f["severity_rationale"] += " Changed from %s to %s during triage." % (old.capitalize(), f["severity"].capitalize())

    # ---------------------------------------------------------------- summary
    def auto_summary(self, vulns, runtimes, libraries) -> tuple[str, list[str]]:
        counts = sev_counts(vulns)
        oos, seen = [], set()
        for x in runtimes + libraries:
            if x["support"]["out_of_support"] and x["id"] not in seen:
                seen.add(x["id"])
                fw = self.fw_by_lib.get(x["id"])
                oos.append(("%s %s" % (fw["name"] if fw else short_name(x), x.get("version") or "")).strip()
                           + " (%s)" % x["support"]["status"])
        n = len(vulns)
        sizes = "%s and %s" % (plural(len(libraries), "package"), plural(len(runtimes), "runtime"))
        integ = [f for f in vulns if f["category"] == "integrity"]
        injection = ("the repository contains %s (%s)" % (
            "a prompt-injection attempt" if len(integ) == 1 else "%d prompt-injection attempts" % len(integ),
            ", ".join(C.dedupe(f["location"]["file"] for f in integ)))) if integ else None
        if self.offline:
            headline = "Offline run: %s inventoried; support status and known vulnerabilities were not checked" % sizes
            suspected = sum(1 for f in vulns if f["category"] == "dependency")
            if suspected:
                headline += "; %s, not verified" % plural(suspected, "suspected vulnerability", "suspected vulnerabilities")
            if injection:
                headline += "; " + injection
            return headline + ".", self.auto_actions(vulns)
        parts = []
        if n:
            parts.append("%s (%s)" % (plural(n, "finding"), join_and("%d %s" % (counts[s], s) for s in C.SEVERITIES if counts[s])))
        elif oos:
            parts.append("No known vulnerabilities found")
        else:
            parts.append("No known vulnerabilities and nothing out of support among %s" % sizes)
        if oos:
            parts.append("out of support: %s%s" % (", ".join(oos[:3]), " and %d more" % (len(oos) - 3) if len(oos) > 3 else ""))
        if injection:
            parts.append(injection)
        headline = "; ".join(parts) + "."
        return headline[0].upper() + headline[1:], self.auto_actions(vulns)

    def auto_actions(self, vulns) -> list[str]:
        by_pkg: dict[str, list] = {}
        for f in vulns:
            if f["affected_package"]:
                by_pkg.setdefault(f["affected_package"], []).append(f)
        actions = []
        for pkg_id, fs in by_pkg.items():
            item = self.items.get(pkg_id) or {}
            version = item.get("version") or ""
            label = ("%s %s" % (short_name(item) or pkg_id, version)).strip()
            deps = [f for f in fs if f["category"] == "dependency"]
            sup = [f for f in fs if f["category"] == "support"]
            fixable = [f for f in deps if f["advisory"] and f["advisory"]["fixed_versions"]]
            unfixed = [f for f in deps if f["rule"] == "osv" and f["status"] == "verified" and not f["advisory"]["fixed_versions"]]
            target = max((f["advisory"]["fixed_versions"][0] for f in fixable), key=C.version_sort_key) if fixable else None
            runtime = pkg_id.startswith("runtime:")
            if sup and (runtime or sup[0]["rule"] == "support-eol"):
                fw = self.fw_by_lib.get(pkg_id)
                what = ("%s %s" % (fw["name"], version)).strip() if fw else label
                text = "%s %s to a supported release line" % ("Move" if runtime else "Upgrade", what)
                if target:
                    text += " (its advisories are fixed in %s or later)" % target
            elif sup:
                alt = (self.support_details.get(pkg_id) or {}).get("alternate_package") or {}
                text = "Replace the %s %s package%s" % (sup[0]["rule"].split("-", 1)[1], label,
                                                        " with %s" % alt["id"] if alt.get("id") else "")
            elif target:
                text = "Upgrade %s → %s" % (label, target)
                if unfixed:
                    text += "; %s no fix yet" % ("1 advisory has" if len(unfixed) == 1 else "%d advisories have" % len(unfixed))
            elif unfixed:
                text = "Replace or mitigate %s: no fixed version is available" % label
            else:
                text = "Review %s" % label
            # within a severity, an out-of-support runtime comes first: it is often the biggest support risk (Step 2)
            actions.append((min(C.SEV_RANK[f["severity"]] for f in fs), 0 if runtime and sup else 1, -len(fs),
                            "%s (%s)" % (text, refs_text(f["id"] for f in fs))))
        for f in vulns:
            if f["category"] == "integrity":
                actions.append((C.SEV_RANK[f["severity"]], 1, -1, "Remove the prompt-injection text from %s and find out "
                                                                  "who added it (%s)" % (f["location"]["file"], f["id"])))
        actions.sort()
        return [a[-1] for a in actions[:5]]

    def review_lists(self, findings) -> dict:
        r = {
            "reachability (high and critical dependency findings, Step 4.7)":
                [f["id"] for f in findings if f["category"] == "dependency" and f["severity"] in ("critical", "high")],
            "integrity (confirm, or suppress with a reason)": [f["id"] for f in findings if f["category"] == "integrity"],
            "severity without a CVSS score or published severity":
                [f["id"] for f in findings if f["category"] == "dependency" and "until reviewed" in f["severity_rationale"]],
            "low confidence (depends on the resolved version)": [f["id"] for f in findings if f["confidence"] == "low"],
            "ignored by a committed osv-scanner.toml": [f["id"] for f in findings if (f.get("hints") or {}).get("ignored_by_repo_config")],
            "dev or build scope only": [f["id"] for f in findings if "Installed only in" in f["severity_rationale"]],
            "found only by a scanner": [f["id"] for f in findings if f["rule"] == "scanner-advisory"
                                        or (f.get("hints") or {}).get("found_only_by_scanner")],
        }
        return {k: sorted(v, key=fid_num) for k, v in r.items() if v}

    # ---------------------------------------------------------------- scan section
    def scan_section(self, args, filtered: list, dropped_transitive: int, notes: list[str]) -> dict:
        mcp = (self.scn or {}).get("mcp") or {}
        scanners = (self.scn or {}).get("scanners") or []
        parts = self.adv.get("parts_run") or []
        checks = ["inventory"]
        if not self.offline:
            checks.append("support")
            if parts:
                checks.append("sca")
        tools = []
        if mcp.get("status") == "used":
            tools.append({"name": "osv-scanner-mcp", "version": mcp.get("version")})
        for s in scanners:
            if s.get("status") == "ran":
                tools.append({"name": s["name"], "version": s.get("version")})
        if not self.offline:
            if "inventory" in parts:
                tools.append({"name": "osv.dev querybatch", "version": "v1"})
            if (self.adv.get("stats") or {}).get("records_fetched"):
                tools.append({"name": "osv.dev vulns API", "version": "v1"})
            for t in self.sup.get("sources_used") or []:
                tools.append({"name": t["name"], "version": t.get("version")})
        missing = []
        if mcp.get("status") == "not-configured":
            missing.append("osv-scanner-mcp")
        for s in scanners:
            if s.get("status") == "not-installed" and s.get("applicable") \
                    and not (s["name"] == "osv-scanner" and mcp.get("status") == "used"):
                missing.append(s["name"])
        gaps = [OFFLINE_GAP] if self.offline else []
        for g in (self.inv.get("gaps") or []) + (self.sup.get("gaps") or []) + (self.adv.get("gaps") or []):
            if not (self.offline and str(g).startswith("Offline")):
                gaps.append(str(g))
        if mcp.get("status") == "skipped-go":
            gaps.append("The osv-scanner MCP scan was not used: its Go call analysis loads Go packages (open question 13). "
                        "The osv-scanner CLI without call analysis, or query_osv.py, covered the Go modules instead")
        if self.scn is None and not self.offline:
            gaps.append("run_scanners.py did not run, so no other scanner was tried (Step 4.4)")
        for s in scanners:
            reason = str(s.get("reason") or "")
            if s.get("status") == "skipped" and "--only/--skip" in reason:
                gaps.append("%s was left out of this run (--only/--skip)" % s["name"])
            elif s.get("status") == "skipped" and reason.startswith("never run"):
                gaps.append("%s is never run: %s" % (s["name"], reason.split(":", 1)[-1].strip()))
        if filtered:
            fc = sev_counts(filtered)
            gaps.append("--severity %s: %s below %s %s not listed (%s)" % (
                args.severity, plural(len(filtered), "finding"), args.severity, "is" if len(filtered) == 1 else "are",
                join_and("%d %s" % (fc[s], s) for s in C.SEVERITIES if fc[s])))
        if dropped_transitive:
            gaps.append("--no-transitive: %s without findings %s left out of the inventory" % (
                plural(dropped_transitive, "transitive package"), "is" if dropped_transitive == 1 else "are"))
        errors = [str(e) for e in (self.inv.get("errors") or []) + (self.sup.get("errors") or [])
                  + (self.adv.get("errors") or []) + ((self.scn or {}).get("errors") or [])]
        if self.scn is not None:
            pass  # run_scanners.py already recorded a failed or skipped MCP scan in its errors
        elif mcp.get("status") == "failed":
            errors.append("The osv-scanner MCP scan failed%s; the fallbacks were used (Step 4.1)"
                          % (": %s" % mcp["reason"] if mcp.get("reason") else ""))
        elif mcp.get("status") == "skipped-private":
            errors.append("The osv-scanner MCP scan was not called: %s" % (
                mcp.get("reason") or "the inventory has private or internal packages, and the scan would send their names "
                                     "to OSV.dev (Step 4.1)"))
        for s in scanners:
            reason = str(s.get("reason") or "")
            if s.get("status") == "skipped" and reason and not any(h in reason for h in HARMLESS_SKIPS) \
                    and "--only/--skip" not in reason and not reason.startswith("never run"):
                errors.append("%s was not run: %s" % (s["name"], reason))
            elif s.get("status") == "failed":
                errors.append("%s failed: %s" % (s["name"], reason or "see raw/scanners.json"))
        errors += [unconfirmed_text(u) for u in self.adv.get("unconfirmed") or []]
        errors += notes
        scanned = []
        for scanner, files in (self.adv.get("coverage_files") or {}).items():
            for f in files or []:
                scanned.append({"file": f.get("file"), "packages": f.get("packages"), "scanner": scanner})
        scope = self.inv.get("scope") or {}
        return {
            "mode": "offline" if self.offline else "online",
            "started_at": self.inv.get("started_at") or self.inv.get("generated_at"),
            "finished_at": C.now_iso(),
            "options": {
                "offline": self.offline, "severity": args.severity, "no_transitive": bool(self.inv_opts.get("no_transitive")),
                "unmaintained_months": (self.sup.get("options") or {}).get("unmaintained_months"),
                "fail_on": args.fail_on, "internal_patterns": list(self.inv_opts.get("internal_patterns") or []),
                "mirror_policy": self.inv_opts.get("mirror_policy"),
            },
            "scope": {"files_scanned": scope.get("files_scanned", 0), "excluded_paths": list(scope.get("excluded_paths") or []),
                      "osv_scanner_configs": [c.get("path") for c in self.inv.get("osv_scanner_configs") or [] if c.get("path")]},
            "coverage": {"checks_run": checks, "tools_used": C.dedupe(tools), "tools_missing": C.dedupe(missing),
                         "ecosystems_unsupported": list(self.inv.get("ecosystems_unsupported") or []),
                         "osv_scanned_files": scanned, "gaps": C.dedupe(gaps)},
            "errors": C.dedupe(errors),
        }

    # ---------------------------------------------------------------- files
    def write_draft(self, findings) -> dict:
        findings = sorted(findings, key=report_order)
        headline, actions = self.auto_summary(findings, self.runtimes, self.libraries)
        data = {
            "tool": {"name": "build_report.py", "version": C.TOOL_VERSION},
            "generated_at": C.now_iso(),
            "about": ("Draft findings for triage. Record judgment in raw/triage.json (references/triage.md), then run "
                      "build_report.py build. The id_map keeps F-IDs stable between runs; don't edit it."),
            "mode": "offline" if self.offline else "online",
            "counts": sev_counts(findings),
            "to_review": self.review_lists(findings),
            "suggested_summary": {"headline": headline, "top_actions": actions},
            "findings": [dict({k: f[k] for k in REPORT_FIELDS}, hints=f.get("hints") or {}) for f in findings],
            "id_map": dict(sorted(self.id_map.items(), key=lambda kv: fid_num(kv[1]))),
        }
        C.write_json(self.raw / DRAFT_NAME, data)
        return data


# --------------------------------------------------------------------------- commands

def cmd_draft(args) -> int:
    b = Builder(Path(args.out))
    findings, _ = b.compute()
    data = b.write_draft(findings)
    triage_path = b.raw / TRIAGE_NAME
    created = args.reset_triage or not triage_path.is_file()
    if created:
        C.write_json(triage_path, EMPTY_TRIAGE)
    counts = data["counts"]
    print("wrote %s: %s (%s)" % (b.raw / DRAFT_NAME, plural(len(findings), "draft finding"),
                                 ", ".join("%d %s" % (counts[s], s) for s in C.SEVERITIES if counts[s]) or "none"))
    print(("created %s: record your triage there" if created else "kept %s: your triage edits are untouched") % triage_path)
    if data["to_review"]:
        print("to review:")
        for k, ids in data["to_review"].items():
            print("  %s: %s" % (k, refs_text(ids, 12)))
    for f in data["findings"][:40]:
        first = f["advisory"]["ids"][0] if f.get("advisory") and f["advisory"]["ids"] else f["rule"]
        print("  %-6s %-8s %-6s %-20s %-44s %s" % (f["id"], f["severity"], f["confidence"], first,
                                                  f["affected_package"] or f["location"]["file"], f["title"][:70]))
    if len(data["findings"]) > 40:
        print("  ... %d more in %s" % (len(data["findings"]) - 40, DRAFT_NAME))
    print("suggested headline: %s" % data["suggested_summary"]["headline"])
    for i, a in enumerate(data["suggested_summary"]["top_actions"], 1):
        print("  %d. %s" % (i, a))
    return 0


def cmd_build(args) -> int:
    out = Path(args.out)
    b = Builder(out)
    triage_path = b.raw / TRIAGE_NAME
    if triage_path.is_file():
        try:
            triage = C.read_json(triage_path)
        except ValueError as e:
            print("error: %s is not valid JSON: %s" % (triage_path, e), file=sys.stderr)
            return 1
        if not isinstance(triage, dict):
            print("error: %s must hold a JSON object" % triage_path, file=sys.stderr)
            return 1
    else:
        b.warnings.append("raw/triage.json not found: the report is built from the draft without triage")
        triage = {}
    unknown = set(triage) - TRIAGE_KEYS
    if unknown:
        b.errors.append("triage.json: unknown key(s) %s (allowed: %s)" % (", ".join(sorted(unknown)), ", ".join(sorted(TRIAGE_KEYS - {"_help"}))))

    b.apply_support_overrides(triage.get("support_overrides") or {})
    findings, dep_by_key = b.compute()
    extra = [f for f in (b.extra_finding(x, i) for i, x in enumerate(triage.get("extra_findings") or [])) if f]
    keys = {f["key"] for f in findings}
    for f in extra:
        if f["key"] in keys:
            b.errors.append("extra finding %s duplicates a finding already in the draft" % f["key"])
    b.assign_ids(extra)
    findings += extra
    by_id = {f["id"]: f for f in findings}
    suppressed = b.parse_suppress(triage.get("suppress") or [], by_id)
    inactive = frozenset(by_id[fid]["key"] for fid in suppressed)
    for f in findings:
        if f["category"] == "support":
            b.finalize_support(f, dep_by_key, inactive)
    b.apply_overrides(triage.get("overrides") or {}, by_id)

    ts = triage.get("summary") or {}
    if not isinstance(ts, dict):
        b.errors.append("summary must be an object with headline and top_actions")
        ts = {}
    if ts.get("headline") is not None and not (isinstance(ts["headline"], str) and ts["headline"].strip()):
        b.errors.append("summary.headline must be a non-empty string or null")
    acts = ts.get("top_actions")
    if acts is not None and not (isinstance(acts, list) and all(isinstance(a, str) and a.strip() for a in acts)):
        b.errors.append("summary.top_actions must be a list of non-empty strings or null")
    notes = triage.get("notes") or []
    if not (isinstance(notes, list) and all(isinstance(n, str) for n in notes)):
        b.errors.append("notes must be a list of strings")
        notes = []

    vulns, supp = [], []
    for f in findings:
        if f["id"] in suppressed:
            adv = f.get("advisory") or {}
            supp.append({"rule": f["rule"], "advisory_id": adv["ids"][0] if adv.get("ids") else None,
                         "affected_package": f["affected_package"],
                         "location": {"file": f["location"]["file"], "line": f["location"]["line"]},
                         "reason": suppressed[f["id"]], "finding_id": f["id"], "title": f["title"]})
        else:
            vulns.append(f)
    unassessed = []
    for f in vulns:
        if f["category"] == "dependency" and f["severity"] in ("critical", "high") and f["reachability"] is None:
            f["reachability"] = {"status": "unknown", "evidence": "Not assessed in this run."}
            unassessed.append(f["id"])
    if unassessed:
        b.warnings.append("%s with no reachability assessment, recorded as unknown: %s. Set overrides.<id>.reachability "
                          "(Step 4.7)" % (plural(len(unassessed), "high or critical finding"), refs_text(unassessed, 12)))
    min_rank = C.SEV_RANK[args.severity]
    filtered = [f for f in vulns if C.SEV_RANK[f["severity"]] > min_rank]
    vulns = sorted((f for f in vulns if C.SEV_RANK[f["severity"]] <= min_rank), key=report_order)

    ids_by_pkg: dict[str, list[str]] = {}
    for f in vulns:
        if f["affected_package"]:
            ids_by_pkg.setdefault(f["affected_package"], []).append(f["id"])
    for x in b.runtimes + b.libraries:
        x["vulnerability_ids"] = sorted(ids_by_pkg.get(x["id"], []), key=fid_num)
    libraries = b.libraries
    if b.inv_opts.get("no_transitive"):
        libraries = [lib for lib in b.libraries if lib["direct"] or lib["vulnerability_ids"]]
    dropped_transitive = len(b.libraries) - len(libraries)
    frameworks = b.frameworks({lib["id"] for lib in libraries})

    headline, actions = b.auto_summary(vulns, b.runtimes, libraries)
    headline = ts.get("headline").strip() if isinstance(ts.get("headline"), str) and ts["headline"].strip() else headline
    actions = [a.strip() for a in acts] if isinstance(acts, list) else actions
    shown = {f["id"] for f in vulns}
    for text in [headline] + actions:
        for ref in re.findall(r"F-\d{3,}", text):
            if ref not in shown:
                b.errors.append("summary refers to %s, which is not among the reported findings (suppressed or below "
                                "--severity?)" % ref)
    if len(actions) > 5:
        b.warnings.append("summary.top_actions has %d entries; the report shows the top 3-5" % len(actions))
    if b.errors:
        print("triage.json has %s; dependency-report.json was not written:" % plural(len(b.errors), "error"), file=sys.stderr)
        for e in b.errors:
            print("  error: %s" % e, file=sys.stderr)
        return 1

    counts = sev_counts(vulns)
    support_counts = {s: 0 for s in C.SUPPORT_STATUSES}
    for x in b.runtimes + libraries:
        support_counts[x["support"]["status"]] += 1
    t = b.inv["target"]
    report = {
        "schema_version": C.SCHEMA_VERSION,
        "report_id": str(uuid.uuid4()),
        "generated_at": C.now_iso(),
        "tool": {"name": C.TOOL_NAME, "version": C.TOOL_VERSION, "agent_model": args.agent_model},
        "target": {"name": t.get("name") or Path(t["path"]).name, "path": t["path"], "vcs": t.get("vcs")},
        "scan": b.scan_section(args, filtered, dropped_transitive, [n.strip() for n in notes if n.strip()]),
        "summary": {
            "risk_rating": next((s for s in C.SEVERITIES if counts[s]), "none"),
            "counts": counts,
            "inventory_counts": {"runtimes": len(b.runtimes), "frameworks": len(frameworks),
                                 "libraries_direct": sum(1 for lib in libraries if lib["direct"]),
                                 "libraries_transitive": sum(1 for lib in libraries if not lib["direct"])},
            "support_counts": support_counts,
            "out_of_support": sum(support_counts[s] for s in C.OUT_OF_SUPPORT),
            "headline": headline,
            "top_actions": actions,
        },
        "inventory": {"languages": list(b.inv.get("languages") or []), "runtimes": b.runtimes,
                      "frameworks": frameworks, "libraries": libraries},
        "vulnerabilities": [{k: f[k] for k in REPORT_FIELDS} for f in vulns],
        "suppressed": sorted(supp, key=lambda s: fid_num(s["finding_id"])),
    }
    report_path = out / REPORT_NAME
    C.write_json(report_path, report)
    b.write_draft(findings)

    print("wrote %s" % report_path)
    print("findings: %d (%s); suppressed: %d; risk: %s" % (
        len(vulns), ", ".join("%d %s" % (counts[s], s) for s in C.SEVERITIES if counts[s]) or "none", len(supp),
        report["summary"]["risk_rating"]))
    print("inventory: %d runtimes, %d frameworks, %d direct + %d transitive libraries; out of support: %d" % (
        len(b.runtimes), len(frameworks), report["summary"]["inventory_counts"]["libraries_direct"],
        report["summary"]["inventory_counts"]["libraries_transitive"], report["summary"]["out_of_support"]))
    if b.new_ids:
        print("new finding IDs not in the last draft: %s" % refs_text(b.new_ids, 12))
    for w in b.warnings:
        print("warning: %s" % w)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Draft findings for triage, then build dependency-report.json.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("draft", help="write raw/findings-draft.json and, if missing, raw/triage.json")
    d.add_argument("--out", required=True, help="output directory (holds raw/)")
    d.add_argument("--reset-triage", action="store_true", help="replace raw/triage.json with an empty one")
    bp = sub.add_parser("build", help="apply raw/triage.json and write dependency-report.json")
    bp.add_argument("--out", required=True, help="output directory (holds raw/)")
    bp.add_argument("--severity", choices=C.SEVERITIES, default="info", help="leave out findings below this level")
    bp.add_argument("--fail-on", choices=C.SEVERITIES, default=None, help="recorded in scan.options for validate_report.py")
    bp.add_argument("--agent-model", default="unknown", help="the model ID of the agent that triaged the findings")
    args = ap.parse_args(argv)
    return cmd_draft(args) if args.cmd == "draft" else cmd_build(args)


if __name__ == "__main__":
    sys.exit(main())
