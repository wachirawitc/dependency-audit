#!/usr/bin/env python3
"""Render dependency-report.html from dependency-report.json (spec §7, hard rule 4).

Usage:
    python render_html.py <report.json> [<report.html>] [--template <path>] [--raw <dir>]

The output defaults to the JSON path with an .html extension, the template to
../templates/report.html.tmpl next to this script, and --raw to the raw/ folder next to the JSON.
Standard library only.

The report is validated again first (validate_report.py). A report that fails validation is still
rendered, with a "Report failed validation" banner at the top (spec §9), and the script exits 1 so the
caller knows. The page is built from the JSON in the browser. This script fills five placeholders:
    __TITLE__       page title (HTML-escaped)
    __VALIDATION__  the validation banner, or nothing (every value HTML-escaped)
    __NOSCRIPT__    static fallback shown when JavaScript is off (every value HTML-escaped)
    __DATA__        the report JSON, with every "<" written as \\u003c so it can't break the <script> block
    __DATA_FILE__   the JSON file name, as a JavaScript string literal
Repository content is untrusted: every value from the report is escaped here, and the
template's script inserts values as text nodes only.
"""
import argparse
import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_report  # noqa: E402

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
PLACEHOLDERS = ("__TITLE__", "__VALIDATION__", "__NOSCRIPT__", "__DATA__", "__DATA_FILE__")

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def script_safe(text):
    """Escape a JSON/JS literal so it can sit inside a <script> element. In JSON, "<" can only
    occur inside strings, where \\u003c decodes to the same character, so the data is unchanged
    while "</script>", "<!--" and "<script" can no longer appear."""
    return text.replace("<", "\\u003c")


def fix_text(finding):
    adv = finding.get("advisory")
    if adv:
        if finding.get("status") == "unverified":
            return "Not verified (offline)"
        fixed = adv.get("fixed_versions") or []
        if fixed:
            return "Upgrade to %s or later" % fixed[0]
        return "Fixed version not given" if finding.get("rule") == "scanner-advisory" else "No fixed version"
    return (finding.get("remediation") or {}).get("summary", "")


def validation_banner(errors):
    if not errors:
        return ""
    e = html.escape
    items = "".join("<li>%s</li>" % e(x) for x in errors[:5])
    more = "<li>… and %d more</li>" % (len(errors) - 5) if len(errors) > 5 else ""
    return ('  <div class="banner banner-error" role="alert"><b>Report failed validation:</b> %d problem%s. The findings '
            'below may be incomplete or inconsistent; run validate_report.py for the full list.<ul>%s%s</ul></div>'
            % (len(errors), "" if len(errors) == 1 else "s", items, more))


def noscript_block(report, data_file_name):
    e = html.escape
    summary = report["summary"]
    packages = {p["id"]: p for p in report["inventory"]["runtimes"] + report["inventory"]["libraries"]}
    rank = {s: i for i, s in enumerate(SEV_ORDER)}

    rows = []
    for f in sorted(report["vulnerabilities"], key=lambda f: (rank.get(f["severity"], 99), f["id"])):
        pkg = packages.get(f.get("affected_package") or "")
        where = "%s %s" % (pkg["name"], pkg.get("version") or "") if pkg else (f.get("location") or {}).get("file") or ""
        rows.append('<tr><td class="mono">%s</td><td>%s</td><td>%s</td><td class="mono">%s</td><td>%s</td></tr>'
                    % (e(f["id"]), e(f["severity"].capitalize()), e(f["title"]), e(where.strip()), e(fix_text(f))))
    if not rows:
        rows.append('<tr><td colspan="5">No vulnerabilities were found by the checks that ran.</td></tr>')

    counts = summary["counts"]
    count_text = ", ".join("%d %s" % (counts[s], s) for s in SEV_ORDER if counts.get(s)) or "none"
    actions = "".join("<li>%s</li>" % e(a) for a in summary.get("top_actions", [])) or "<li>Nothing needs action.</li>"

    return """  <noscript>
    <div class="noscript">
      <p class="lead">%s</p>
      <p><b>Overall risk:</b> %s · <b>Vulnerabilities:</b> %s · <b>Out of support:</b> %d</p>
      <div class="card"><h3>What to do first</h3><ol>%s</ol></div>
      <div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Package</th><th>Fix</th></tr></thead>
        <tbody>%s</tbody>
      </table></div>
      <p class="muted small">Turn on JavaScript for filters, the full dependency list and finding details. All data is in %s.</p>
    </div>
  </noscript>""" % (e(summary["headline"]), e(summary["risk_rating"]), e(count_text),
                    summary["out_of_support"], actions, "".join(rows), e(data_file_name))


def render(report, template, data_file_name, validation_errors=()):
    for ph in PLACEHOLDERS:
        if ph not in template:
            raise ValueError("template is missing placeholder %s" % ph)
    try:
        title = "%s · Dependency audit" % ((report.get("target") or {}).get("name") or "Project")
        noscript = noscript_block(report, data_file_name)
    except (KeyError, TypeError, AttributeError, ValueError):
        # a report too broken for the fallback table still gets a page and its banner (spec §9)
        title = "Dependency audit"
        noscript = "  <noscript><p>This report could not be summarised. All data is in %s.</p></noscript>" % html.escape(data_file_name)
    values = {
        "__TITLE__": html.escape(title),
        "__VALIDATION__": validation_banner(list(validation_errors)),
        "__NOSCRIPT__": noscript,
        "__DATA_FILE__": script_safe(json.dumps(data_file_name)),
        "__DATA__": script_safe(json.dumps(report, ensure_ascii=False, separators=(",", ":"))),
    }
    # One pass over the template, so placeholder-like text inside report values is never replaced.
    return re.sub("|".join(re.escape(p) for p in sorted(PLACEHOLDERS, key=len, reverse=True)),
                  lambda m: values[m.group(0)], template)


def main(argv=None):
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Render dependency-report.html from dependency-report.json.")
    ap.add_argument("json", type=Path, help="report JSON")
    ap.add_argument("out", type=Path, nargs="?", help="output HTML (default: JSON path with .html)")
    ap.add_argument("--template", type=Path, default=here.parent / "templates" / "report.html.tmpl")
    ap.add_argument("--raw", type=Path, help="raw evidence folder for validation (default: raw/ next to the JSON)")
    args = ap.parse_args(argv)

    report = json.loads(args.json.read_text(encoding="utf-8"))
    errors, _warnings = validate_report.validate(report, args.raw or args.json.resolve().parent / "raw",
                                               report_dir=args.json.resolve().parent)
    out_path = args.out or args.json.with_suffix(".html")
    page = render(report, args.template.read_text(encoding="utf-8"), args.json.name, errors)
    out_path.write_text(page, encoding="utf-8")
    print("wrote %s (%d bytes)" % (out_path, len(page.encode("utf-8"))))
    if errors:
        print("the report failed validation (%d problem%s); the page shows a banner. First: %s"
              % (len(errors), "" if len(errors) == 1 else "s", errors[0]), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
