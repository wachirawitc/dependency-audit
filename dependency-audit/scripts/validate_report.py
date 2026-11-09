#!/usr/bin/env python3
"""Step 7 of the dependency audit: check dependency-report.json against schema/report.schema.json and the
cross-reference rules in spec §6.

Usage:
    python validate_report.py <report.json> [--raw <dir>] [--fail-on <severity>] [--json]

--raw defaults to the raw/ folder next to the report. It holds the evidence advisory IDs are checked
against (raw/osv/<ID>.json and raw/scanner-results.json).

Exit codes: 0 valid; 1 invalid; 2 valid, but a finding is at or above --fail-on (open question 11), so CI
can run this after the agent. Standard library only: the schema check implements the JSON Schema 2020-12
keywords that report.schema.json uses.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
SCHEMA_PATH = SKILL_DIR / "schema" / "report.schema.json"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SUPPORT_STATUSES = ["supported", "security-only", "end-of-life", "deprecated", "unmaintained", "unknown"]
OUT_OF_SUPPORT = {"end-of-life", "deprecated", "unmaintained"}
RULE_CATEGORY = {"osv": "dependency", "scanner-advisory": "dependency", "support-eol": "support",
                 "support-deprecated": "support", "support-unmaintained": "support",
                 "prompt-injection-attempt": "integrity"}
SUPPORT_RULE = {"end-of-life": "support-eol", "deprecated": "support-deprecated", "unmaintained": "support-unmaintained"}
FINDING_SCOPES = {"runtime", "optional"}

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


# --------------------------------------------------------------------------- JSON Schema (subset)

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def schema_errors(value, schema: dict, root: dict | None = None, path: str = "$") -> list[str]:
    """Errors for the keywords the report schema uses: $ref (local), type, const, enum, properties, required,
    additionalProperties, items, minItems, minLength, pattern, minimum, maximum, anyOf, oneOf."""
    root = root or schema
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            return ["%s: unsupported $ref %s" % (path, ref)]
        target = root
        for part in ref[2:].split("/"):
            target = target[part]
        return schema_errors(value, target, root, path)
    errs = []
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_TYPES[t](value) for t in types):
            return ["%s: expected %s, got %s" % (path, " or ".join(types), _type_name(value))]
    if "const" in schema and value != schema["const"]:
        errs.append("%s: must be %s" % (path, json.dumps(schema["const"])))
    if "enum" in schema and value not in schema["enum"]:
        errs.append("%s: %s is not one of %s" % (path, json.dumps(value), ", ".join(json.dumps(e) for e in schema["enum"])))
    if isinstance(value, dict):
        props = schema.get("properties") or {}
        for k in schema.get("required") or []:
            if k not in value:
                errs.append("%s: missing required field '%s'" % (path, k))
        for k, v in value.items():
            if k in props:
                errs += schema_errors(v, props[k], root, "%s.%s" % (path, k))
            elif schema.get("additionalProperties") is False:
                errs.append("%s: unexpected field '%s'" % (path, k))
            elif isinstance(schema.get("additionalProperties"), dict):
                errs += schema_errors(v, schema["additionalProperties"], root, "%s.%s" % (path, k))
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errs.append("%s: needs at least %d item(s)" % (path, schema["minItems"]))
        if "items" in schema:
            for i, item in enumerate(value):
                errs += schema_errors(item, schema["items"], root, "%s[%d]" % (path, i))
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append("%s: must not be empty" % path if schema["minLength"] == 1 else "%s: too short" % path)
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append("%s: %s does not match %s" % (path, json.dumps(value)[:80], schema["pattern"]))
    if _TYPES["number"](value):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append("%s: must be at least %s" % (path, schema["minimum"]))
        if "maximum" in schema and value > schema["maximum"]:
            errs.append("%s: must be at most %s" % (path, schema["maximum"]))
    for key in ("anyOf", "oneOf"):
        if key in schema:
            matches = sum(1 for sub in schema[key] if not schema_errors(value, sub, root, path))
            if matches == 0 or (key == "oneOf" and matches > 1):
                errs.append("%s: does not match %s the allowed shapes" % (path, "any of" if key == "anyOf" else "exactly one of"))
    return errs


def _type_name(v) -> str:
    for name in ("null", "boolean", "integer", "number", "string", "array", "object"):
        if _TYPES[name](v):
            return name
    return type(v).__name__


# --------------------------------------------------------------------------- credentials (Step 1)

_URL_USERINFO = re.compile(r"\bhttps?://([^/\s\"'<>@]+)@[^\s/]", re.I)
_SECRET_VALUE = re.compile(r"(?i)(_authToken|_auth|_password|password|passwd|ClearTextPassword)\s*[=:]\s*\"?([^\s\"',;<>]+)")
_TOKENS = [re.compile(p) for p in (r"\bnpm_[A-Za-z0-9]{36}\b", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
                                   r"\boy2[a-z0-9]{43}\b", r"\bAKIA[0-9A-Z]{16}\b")]
_REDACTED = re.compile(r"^.{0,4}…\(\d+\)$")
_PLACEHOLDER = re.compile(r"^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|\*+|<[^>]*>|x+|\.\.\.|…)$")


def credential_problems(report) -> list[str]:
    out = []

    def walk(v, path):
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, "%s.%s" % (path, k))
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, "%s[%d]" % (path, i))
        elif isinstance(v, str):
            for m in _URL_USERINFO.finditer(v):
                if not _REDACTED.match(m.group(1)):
                    out.append("%s: a URL carries user-info (credentials must never appear in full, Step 1)" % path)
                    break
            for m in _SECRET_VALUE.finditer(v):
                val = m.group(2)
                if not _REDACTED.match(val) and not _PLACEHOLDER.match(val) and not val.startswith("…"):
                    out.append("%s: a %s value appears in full (show only the first 4 characters, … and the length)" % (path, m.group(1)))
                    break
            for pat in _TOKENS:
                if pat.search(v):
                    out.append("%s: a registry or access token appears in full" % path)
                    break

    walk(report, "$")
    return out


# --------------------------------------------------------------------------- cross-references (spec §6)

def load_osv_ids(raw: Path) -> set[str] | None:
    folder = raw / "osv"
    if not folder.is_dir():
        return None
    ids = set()
    for p in folder.glob("*.json"):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict):
            ids.add(str(rec.get("id") or p.stem))
            ids.update(str(a) for a in rec.get("aliases") or [])
    return ids


def load_scanner_ids(raw: Path) -> dict[str, set[str]] | None:
    p = raw / "scanner-results.json"
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    out: dict[str, set[str]] = {}
    for m in data.get("matches") or []:
        if isinstance(m, dict):
            out.setdefault(str(m.get("scanner")), set()).update(str(i) for i in m.get("ids") or [])
    return out


def cross_errors(r: dict, raw: Path | None) -> tuple[list[str], list[str]]:
    errs, warns = [], []
    inv, vulns, supp = r["inventory"], r["vulnerabilities"], r["suppressed"]
    libs, rts, fws = inv["libraries"], inv["runtimes"], inv["frameworks"]
    sample = bool(r.get("sample"))
    offline = r["scan"]["mode"] == "offline"

    # unique ids
    seen = set()
    for f in vulns:
        if f["id"] in seen:
            errs.append("finding id %s is used twice" % f["id"])
        seen.add(f["id"])
    for s in supp:
        if s.get("finding_id") in seen:
            errs.append("suppressed entry %s has the id of a reported finding" % s["finding_id"])
    keys = set()
    for lib in libs:
        k = (lib["id"], lib.get("manifest"))
        if k in keys:
            errs.append("library %s appears twice for manifest %s (id + manifest must be unique)" % k)
        keys.add(k)
    rt_ids = [rt["id"] for rt in rts]
    if len(set(rt_ids)) != len(rt_ids):
        errs.append("a runtime id is used twice")
    known = set(rt_ids) | {lib["id"] for lib in libs}
    by_id = {f["id"]: f for f in vulns}

    # findings: shape rules and references
    for f in vulns:
        fid, cat, rule = f["id"], f["category"], f["rule"]
        if RULE_CATEGORY.get(rule) != cat:
            errs.append("%s: rule %s doesn't belong to category %s" % (fid, rule, cat))
        pkg = f["affected_package"]
        if cat == "integrity":
            if pkg is not None:
                errs.append("%s: integrity findings have affected_package null (hard rule 6)" % fid)
            if f["advisory"] is not None:
                errs.append("%s: integrity findings have advisory null" % fid)
            snip = f["location"].get("snippet")
            if snip is not None and len(snip.split("\n")) > 5:
                errs.append("%s: snippet has more than 5 lines (hard rule 3)" % fid)
            if f["location"].get("line") is None:
                errs.append("%s: integrity findings need location.line (hard rule 3)" % fid)
        elif pkg is None:
            errs.append("%s: %s findings need affected_package" % (fid, cat))
        elif pkg not in known:
            errs.append("%s: affected_package %s is not a library or runtime id in the inventory" % (fid, pkg))
        if cat == "support" and f["advisory"] is not None:
            errs.append("%s: support findings have advisory null" % fid)
        if cat == "dependency":
            adv = f["advisory"]
            if adv is None:
                errs.append("%s: dependency findings need an advisory object" % fid)
            elif f["status"] == "verified":
                if not adv["ids"] or not adv["source"]:
                    errs.append("%s: a verified dependency finding needs advisory.ids and advisory.source (hard rule 2)" % fid)
                if rule == "osv" and adv["source"] != "osv.dev":
                    errs.append("%s: rule osv needs advisory.source osv.dev" % fid)
                if rule == "scanner-advisory" and adv["source"] == "osv.dev":
                    errs.append("%s: rule scanner-advisory names the scanner as advisory.source" % fid)
            elif adv["ids"]:
                errs.append("%s: an unverified finding has advisory.ids [] (hard rule 2)" % fid)
        if offline and f["advisory"] and f["advisory"]["ids"]:
            errs.append("%s: an offline report holds no advisory IDs (hard rule 2)" % fid)
        if offline and f["status"] == "verified" and cat == "dependency":
            errs.append("%s: dependency findings in an offline report are unverified (hard rule 2)" % fid)

    # vulnerability_ids agree in both directions
    expected: dict[str, set] = {}
    for f in vulns:
        if f["affected_package"]:
            expected.setdefault(f["affected_package"], set()).add(f["id"])
    for item in rts + libs:
        listed = set(item["vulnerability_ids"])
        for x in listed - set(by_id):
            errs.append("%s lists %s in vulnerability_ids, but there is no such finding" % (item["id"], x))
        missing = expected.get(item["id"], set()) - listed
        extra = {x for x in listed & set(by_id) if by_id[x]["affected_package"] != item["id"]}
        if missing:
            errs.append("%s: vulnerability_ids misses %s" % (item["id"], ", ".join(sorted(missing))))
        if extra:
            errs.append("%s: vulnerability_ids lists %s, which affect another package" % (item["id"], ", ".join(sorted(extra))))

    # summary counts
    s = r["summary"]
    counts = {k: 0 for k in SEVERITIES}
    for f in vulns:
        counts[f["severity"]] += 1
    if s["counts"] != counts:
        errs.append("summary.counts %s doesn't match the findings %s" % (json.dumps(s["counts"]), json.dumps(counts)))
    risk = next((k for k in SEVERITIES if counts[k]), "none")
    if s["risk_rating"] != risk:
        errs.append("summary.risk_rating is %s, but the highest finding severity is %s (open question 19)" % (s["risk_rating"], risk))
    ic = {"runtimes": len(rts), "frameworks": len(fws), "libraries_direct": sum(1 for x in libs if x["direct"]),
          "libraries_transitive": sum(1 for x in libs if not x["direct"])}
    if s["inventory_counts"] != ic:
        errs.append("summary.inventory_counts %s doesn't match the inventory %s" % (json.dumps(s["inventory_counts"]), json.dumps(ic)))
    sc = {k: 0 for k in SUPPORT_STATUSES}
    for item in rts + libs:
        sc[item["support"]["status"]] += 1
    if s["support_counts"] != sc:
        errs.append("summary.support_counts %s doesn't match the inventory %s" % (json.dumps(s["support_counts"]), json.dumps(sc)))
    oos = sum(sc[k] for k in OUT_OF_SUPPORT)
    if s["out_of_support"] != oos:
        errs.append("summary.out_of_support is %d, but %d runtimes and libraries are out of support" % (s["out_of_support"], oos))
    for text in [s["headline"]] + s["top_actions"]:
        for ref in re.findall(r"F-\d{3,}", text):
            if ref not in by_id:
                errs.append("summary refers to %s, which is not a reported finding" % ref)

    # support objects
    for kind, items in (("runtime", rts), ("framework", fws), ("library", libs)):
        for item in items:
            sup = item["support"]
            label = "%s %s" % (kind, item.get("id") or item.get("name"))
            if sup["out_of_support"] != (sup["status"] in OUT_OF_SUPPORT):
                errs.append("%s: out_of_support must be %s for status %s" % (label, sup["status"] in OUT_OF_SUPPORT, sup["status"]))
            if sup["status"] != "unknown" and not sup["source"]:
                errs.append("%s: support.source is required for status %s (hard rule 2)" % (label, sup["status"]))
            if sup["eol_date"] and not sup["source"]:
                errs.append("%s: an eol_date needs a source fetched in this run (hard rule 2)" % label)
            if offline and sup["status"] != "unknown":
                errs.append("%s: support status is unknown in an offline report (hard rule 2)" % label)
    for fw in fws:
        if fw.get("library_id"):
            cands = [x for x in libs if x["id"] == fw["library_id"]]
            if not cands:
                errs.append("framework %s: library_id %s is not in the inventory" % (fw["name"], fw["library_id"]))
                continue
        else:
            cands = [x for x in libs if fw.get("package") and x["name"] == fw["package"] and x["version"] == fw["version"]
                     and x["ecosystem"] == fw.get("ecosystem")]
        if fw.get("manifest") and any(x.get("manifest") == fw["manifest"] for x in cands):
            cands = [x for x in cands if x.get("manifest") == fw["manifest"]]
        if cands and not any(x["support"] == fw["support"] for x in cands):
            errs.append("framework %s: support differs from its package's" % fw["name"])
        if not cands and fw["support"]["status"] != "unknown":
            errs.append("framework %s: support status %s but no matching library to take it from" % (fw["name"], fw["support"]["status"]))

    # out-of-support items have support findings, and support findings point at out-of-support items
    threshold = SEV_RANK.get((r["scan"].get("options") or {}).get("severity") or "info", 4)
    support_hits = {}
    for f in vulns:
        if f["category"] == "support":
            support_hits.setdefault(f["affected_package"], []).append(f["rule"])
    for x in supp:
        if RULE_CATEGORY.get(x["rule"]) == "support" and x.get("affected_package"):
            support_hits.setdefault(x["affected_package"], []).append(x["rule"])
    items = {}
    for rt in rts:
        if rt["support"]["out_of_support"]:
            items[rt["id"]] = (rt["support"]["status"], "high")
    for lib in libs:
        if lib["support"]["out_of_support"] and lib["scope"] in FINDING_SCOPES:
            items.setdefault(lib["id"], (lib["support"]["status"], "medium"))
    for item_id, (status, lowest) in items.items():
        rules = support_hits.get(item_id, [])
        if SUPPORT_RULE[status] in rules:
            continue
        if not rules and SEV_RANK[lowest] > threshold:
            continue  # below --severity: left out by the option, which scan.coverage.gaps records
        errs.append("%s is %s but has no %s finding (Step 3)" % (item_id, status, SUPPORT_RULE[status]))
    statuses = {}
    for item in rts + libs:
        statuses.setdefault(item["id"], set()).add(item["support"]["status"])
    for f in vulns:
        if f["category"] == "support" and f["affected_package"] in statuses:
            want = {k for k, v in SUPPORT_RULE.items() if v == f["rule"]}
            if not statuses[f["affected_package"]] & want:
                errs.append("%s: %s finding, but %s has support status %s" % (
                    f["id"], f["rule"], f["affected_package"], ", ".join(sorted(statuses[f["affected_package"]]))))

    # advisory IDs come from this run's evidence (hard rule 2)
    osv_findings = [f for f in vulns if f["advisory"] and f["advisory"]["source"] == "osv.dev" and f["advisory"]["ids"]]
    scanner_findings = [f for f in vulns if f["advisory"] and f["advisory"]["ids"] and f["advisory"]["source"] not in (None, "osv.dev")]
    if sample:
        warns.append("sample report: advisory IDs and file paths are not checked against raw/ or the target")
    elif raw is None or not raw.is_dir():
        if osv_findings or scanner_findings:
            errs.append("raw/ folder not found, so advisory IDs can't be checked against this run's records (hard rule 2)")
    else:
        osv_ids = load_osv_ids(raw)
        if osv_findings and osv_ids is None:
            errs.append("raw/osv/ not found, so OSV advisory IDs can't be checked (hard rule 2)")
        elif osv_ids is not None:
            for f in osv_findings:
                bad = [i for i in f["advisory"]["ids"] if i not in osv_ids]
                if bad:
                    errs.append("%s: %s not found among the OSV records saved in raw/osv/ (hard rule 2)" % (f["id"], ", ".join(bad)))
        scanner_ids = load_scanner_ids(raw)
        for f in scanner_findings:
            pool = (scanner_ids or {}).get(f["advisory"]["source"])
            bad = [i for i in f["advisory"]["ids"] if pool is None or i not in pool]
            if bad:
                errs.append("%s: %s not found in raw/scanner-results.json for %s (hard rule 2)" % (f["id"], ", ".join(bad), f["advisory"]["source"]))

    # evidence files exist under the target (hard rule 3)
    target = Path(r["target"]["path"])
    if not sample:
        if not target.is_dir():
            errs.append("target.path %s is not a folder on this machine" % r["target"]["path"])
        else:
            for f in vulns:
                p = Path(f["location"]["file"])
                if p.is_absolute() or ".." in p.parts or not (target / p).is_file():
                    errs.append("%s: location.file %s is not a file under target.path" % (f["id"], f["location"]["file"]))
    return errs, warns


def validate(report, raw: Path | None = None, schema: dict | None = None) -> tuple[list[str], list[str]]:
    """(errors, warnings). Errors make the report invalid."""
    schema = schema or json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errs = schema_errors(report, schema)
    if errs:
        return errs, []  # cross-checks assume the shape is right
    errs = credential_problems(report)
    more, warns = cross_errors(report, raw)
    return errs + more, warns


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate dependency-report.json (schema and cross-references).")
    ap.add_argument("report", type=Path)
    ap.add_argument("--raw", type=Path, help="raw evidence folder (default: raw/ next to the report)")
    ap.add_argument("--fail-on", choices=SEVERITIES, help="exit 2 when a finding is at or above this severity")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print("invalid: %s can't be read as JSON (%s)" % (args.report, e))
        return 1
    raw = args.raw or args.report.resolve().parent / "raw"
    errs, warns = validate(report, raw)
    at_or_above = []
    if args.fail_on and not errs:
        limit = SEV_RANK[args.fail_on]
        at_or_above = [f["id"] for f in report["vulnerabilities"] if SEV_RANK[f["severity"]] <= limit]
    code = 1 if errs else (2 if at_or_above else 0)
    if args.json:
        print(json.dumps({"valid": not errs, "errors": errs, "warnings": warns, "fail_on": args.fail_on,
                          "findings_at_or_above": at_or_above, "exit_code": code}, indent=2, ensure_ascii=False))
        return code
    for w in warns:
        print("warning: %s" % w)
    if errs:
        print("invalid: %d problem(s) in %s" % (len(errs), args.report))
        for e in errs[:200]:
            print("  - %s" % e)
        if len(errs) > 200:
            print("  ... %d more" % (len(errs) - 200))
    else:
        print("valid: %s (%d findings, %d libraries, %d runtimes)" % (
            args.report, len(report["vulnerabilities"]), len(report["inventory"]["libraries"]), len(report["inventory"]["runtimes"])))
        if at_or_above:
            print("fail-on %s: %d finding(s) at or above it: %s" % (args.fail_on, len(at_or_above), ", ".join(at_or_above[:20])
                                                                   + (" …" if len(at_or_above) > 20 else "")))
    return code


if __name__ == "__main__":
    sys.exit(main())
