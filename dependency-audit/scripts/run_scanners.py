#!/usr/bin/env python3
"""Steps 4.1 (CLI fallback) and 4.4 of the dependency audit: run the scanners that are installed, read-only.

Usage:
    python run_scanners.py --out <dir> [--mcp-status STATUS] [--mcp-version V] [--mcp-error TEXT]
                           [--osv-cli auto|always|never] [--only a,b] [--skip a,b] [--timeout SECONDS]

--mcp-status records what happened to the osv-scanner MCP scan (Step 4.1), for the report's coverage:
    used             the scan ran; its text is in raw/osv-mcp-scan.txt (the default when that file exists)
    not-configured   there is no osv-scanner MCP server (the default otherwise)
    failed           the tool errored or timed out (say what in --mcp-error)
    skipped-private  not called because the inventory has private packages
    skipped-go       not called because the repository has Go modules: the MCP scan always runs Go call
                     analysis (open question 13), so the CLI runs instead with --no-call-analysis=all
    skipped-offline  not called because the run is offline

--osv-cli auto (the default) runs the osv-scanner CLI whenever the MCP scan didn't run, unless the
inventory has private packages or the run is offline.

Scanners and how each stays read-only (hard rule 5). Every scanner runs from a scratch folder under
raw/scanners/, never from the project, so repository config such as .npmrc credentials, .trivyignore,
.bundler-audit.yml or composer's audit.ignore can't steer or hide results:
    osv-scanner          scan source -r --format json --config <empty file> --no-call-analysis=all
                         --x-disable-plugins=directory, on raw/scan-input/ (copies of the manifests and
                         lockfiles only: hard rule 0, no source file is ever in reach)
    npm-audit            npm audit --json --package-lock-only, on copies of package.json + the lockfile,
                         against the public registry
    pip-audit            pip-audit -f json -r <fully pinned requirements file> --no-deps --disable-pip
    cargo-audit          cargo audit --json --file <Cargo.lock>
    bundle-audit         bundle-audit check --update --format json, on a copy of Gemfile.lock
    composer-audit       composer audit --format=json --locked --no-plugins --no-scripts, on copies of
                         composer.json (minus its audit settings and scripts) and composer.lock
    dotnet-list-package  dotnet list <project> package --vulnerable --include-transitive --format json,
                         only for projects already restored (obj/project.assets.json); never restores
    trivy                trivy fs --scanners vuln --format json --offline-scan --ignorefile <empty file>,
                         on raw/scan-input/
    govulncheck          never run: it loads Go packages through the Go toolchain (open question 13)
When the inventory has private packages, scanners that would send package names to a public service
(osv-scanner, npm-audit, pip-audit, composer-audit) are skipped, and so is dotnet-list-package when a
private NuGet feed is configured (it would call that feed with the repository's credentials). Offline
runs no scanners (open question 20).

Outputs under <out>/raw/: osv-cli.json (the CLI's JSON), scanner-results.json (normalized matches, one
per advisory per package, for query_osv.py), scanners.json (what ran, what was skipped and why, tool
versions), and each scanner's raw output in scanners/. Exit code 0 even when a scanner fails: a failure
is recorded, never fatal (spec §9).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

SCANNERS = ("osv-scanner", "npm-audit", "pip-audit", "cargo-audit", "bundle-audit", "composer-audit",
            "dotnet-list-package", "trivy", "govulncheck")
MCP_STATUSES = ("used", "not-configured", "failed", "skipped-private", "skipped-go", "skipped-offline")
SENDS_NAMES_TO = {"osv-scanner": "OSV.dev and deps.dev", "npm-audit": "the npm registry", "pip-audit": "PyPI",
                  "composer-audit": "Packagist"}
# Which packages each of those scanners sends: osv-scanner sends every ecosystem it finds, the others only their own.
SENDS_ECOSYSTEMS = {"osv-scanner": None, "npm-audit": {"npm"}, "pip-audit": {"PyPI"}, "composer-audit": {"Packagist"}}
SAFE_CMD_ARG = re.compile(r"^[A-Za-z0-9_.,:=/\\~+@-]+$")
GHSA_IN_URL = re.compile(r"(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})", re.I)
TRIVY_ECOSYSTEM = {"npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm", "node-pkg": "npm", "pip": "PyPI",
                   "pipenv": "PyPI", "poetry": "PyPI", "uv": "PyPI", "python-pkg": "PyPI", "gomod": "Go", "gobinary": "Go",
                   "cargo": "crates.io", "rust-binary": "crates.io", "bundler": "RubyGems", "gemspec": "RubyGems",
                   "composer": "Packagist", "composer-vendor": "Packagist", "nuget": "NuGet", "dotnet-core": "NuGet",
                   "packages-props": "NuGet", "pom": "Maven", "gradle": "Maven", "jar": "Maven", "sbt": "Maven",
                   "pub": "Pub", "swift": "SwiftURL", "cocoapods": "CocoaPods", "mix": "Hex", "conan": "ConanCenter"}


class ToolError(Exception):
    pass


def ghsa_ids(*texts) -> list[str]:
    out = []
    for t in texts:
        for m in GHSA_IN_URL.finditer(str(t or "")):
            out.append("GHSA-" + m.group(1)[5:].lower())
    return C.dedupe(out)


def range_contains(spec: str | None, version: str) -> bool | None:
    """Does a comparator range such as '<6.2.4 || >=6.3.0 <6.3.3' (npm audit's form) contain version?
    None when the range uses syntax this doesn't evaluate (caret, tilde, wildcards)."""
    if not spec or not version:
        return None
    for alt in spec.split("||"):
        alt = alt.strip()
        if alt in ("*", ""):
            return True
        if re.search(r"[\^~xX]|\s-\s", alt):
            return None
        comps = re.findall(r"(<=|>=|<|>|=)?\s*v?(\d[\w.\-+]*)", alt)
        if not comps:
            return None
        ok = True
        for op, ver in comps:
            c = C.compare_versions(version, ver)
            ok = ok and {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}.get(op, c == 0)
        if ok:
            return True
    return False


def under_excluded(path: str, excluded) -> bool:
    f = "/" + (path or "").strip("/") + "/"
    return any(e.strip("/") and ("/" + e.strip("/") + "/") in f for e in excluded or [])


class Runner:
    def __init__(self, out: Path, inv: dict, args):
        self.raw = C.raw_dir(out)
        self.work = self.raw / "scanners"
        self.inv = inv
        self.args = args
        self.target = Path((inv.get("target") or {}).get("path") or ".")
        # hard rule 0: osv-scanner and trivy read only this staged copy of the manifests and lockfiles
        sp = (inv.get("target") or {}).get("scan_path")
        self.scan_path = Path(sp) if sp and Path(sp).is_dir() else None
        self.excluded = (inv.get("scope") or {}).get("excluded_paths") or []
        self.offline = bool((inv.get("options") or {}).get("offline"))
        self.timeout = args.timeout
        self.statuses: list[dict] = []
        self.matches: list[dict] = []
        self.errors: list[str] = []
        libs = inv.get("libraries") or []
        self.private_libs = [lib for lib in libs if lib.get("private")]
        self.maven_private = inv.get("maven_private") or []
        self.private_reason = self.private_for(None)
        self.private_nuget = [r["host"] for r in (inv.get("registries") or {}).get("private") or [] if r.get("ecosystem") == "NuGet"]
        self.manifests = inv.get("manifests") or []
        self.libs_by_manifest: dict[str, list] = {}
        for lib in libs:
            for key in {lib.get("manifest"), lib.get("lockfile")} - {None}:
                self.libs_by_manifest.setdefault(key, []).append(lib)
        txt = self.raw / "osv-mcp-scan.txt"
        self.mcp_status = args.mcp_status or ("used" if txt.is_file() else ("skipped-offline" if self.offline else "not-configured"))
        only = {s.strip() for s in (args.only or "").split(",") if s.strip()}
        skip = {s.strip() for s in (args.skip or "").split(",") if s.strip()}
        unknown = (only | skip) - set(SCANNERS)
        if unknown:
            raise SystemExit("error: unknown scanner name(s): %s (known: %s)" % (", ".join(sorted(unknown)), ", ".join(SCANNERS)))
        self.selected = [s for s in SCANNERS if (not only or s in only) and s not in skip]

    # ---------------------------------------------------------------- helpers
    def private_for(self, ecosystems: set | None) -> str | None:
        """Why a scanner that sends these ecosystems' package names (None: all of them) must not run, or None."""
        libs = [lib for lib in self.private_libs if ecosystems is None or lib["ecosystem"] in ecosystems]
        if libs:
            kinds = sorted({lib["ecosystem"] for lib in libs})
            return "the inventory has %d private %s package%s" % (len(libs), "/".join(kinds), "" if len(libs) == 1 else "s")
        if self.maven_private and (ecosystems is None or "Maven" in ecosystems):
            return "the POM uses a private Maven repository (%s)" % "; ".join(self.maven_private)
        return None

    def files(self, pattern: str, kind: str | None = None) -> list[str]:
        rx = re.compile(pattern)
        return [m["path"] for m in self.manifests if rx.search(m["path"]) and (kind is None or m["kind"] == kind)
                and not under_excluded(m["path"], self.excluded)]

    def status(self, name: str, state: str, reason: str | None = None, **extra) -> dict:
        st = {"name": name, "status": state, "reason": reason, "version": None, "runs": []}
        st.update(extra)
        self.statuses.append(st)
        return st

    def scratch(self, name: str, n: int) -> Path:
        d = self.work / ("%s-%d" % (name, n))
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        return d

    def run_tool(self, exe: str, args: list[str], cwd: Path, timeout: int | None = None):
        if exe.lower().endswith((".bat", ".cmd")) and any(not SAFE_CMD_ARG.match(a) for a in args):
            # cmd.exe re-parses the arguments of a batch wrapper, so a path from the repository could inject commands
            raise ToolError("refused to pass a path through the batch wrapper %s" % exe)
        env = dict(os.environ, NO_COLOR="1", NPM_CONFIG_UPDATE_NOTIFIER="false", NPM_CONFIG_FUND="false",
                   NPM_CONFIG_AUDIT_LEVEL="info", COMPOSER_NO_INTERACTION="1", TRIVY_NO_PROGRESS="true",
                   PIP_DISABLE_PIP_VERSION_CHECK="1")
        try:
            return subprocess.run([exe] + args, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=timeout or self.timeout, env=env, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise ToolError("timed out after %d s" % (timeout or self.timeout))
        except OSError as e:
            raise ToolError(str(e))

    def version_of(self, exe: str, args=("--version",)) -> str | None:
        try:
            r = self.run_tool(exe, list(args), cwd=self.work, timeout=60)
        except ToolError:
            return None
        m = re.search(r"\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z]+)?", (r.stdout or "") + " " + (r.stderr or ""))
        return m.group(0) if m else None

    def save(self, name: str, text: str) -> str:
        p = self.work / name
        p.write_text(text or "", encoding="utf-8")
        return C.posix(p.relative_to(self.raw))

    def add_match(self, scanner, ecosystem, package, version, ids, file, facts=None):
        ids = C.dedupe([i for i in ids if i])
        if not ids or not package:
            return
        self.matches.append({"scanner": scanner, "ecosystem": ecosystem, "package": package, "version": version or None,
                             "ids": ids, "file": file, "facts": {k: v for k, v in (facts or {}).items() if v not in (None, "", [])}})

    def gate(self, name: str, applicable: list[str] | bool, exe: str | None, sends_names: bool = False):
        """Record why a scanner doesn't run, or return True when it should."""
        if name not in self.selected:
            self.status(name, "skipped", "left out with --only/--skip")
        elif self.offline:
            self.status(name, "skipped", "offline run (open question 20)")
        elif not applicable:
            self.status(name, "not-applicable", "no files it reads")
        elif sends_names and self.private_for(SENDS_ECOSYSTEMS[name]):
            self.status(name, "skipped", "%s; %s would send package names to %s (Step 4.4)" % (
                self.private_for(SENDS_ECOSYSTEMS[name]), name, SENDS_NAMES_TO[name]), applicable=applicable)
        elif not exe:
            self.status(name, "not-installed", None, applicable=applicable)
        else:
            return True
        return False

    # ---------------------------------------------------------------- osv-scanner CLI
    def osv_cli(self):
        name = "osv-scanner"
        cli_out = self.raw / "osv-cli.json"
        if cli_out.exists():
            cli_out.unlink()                      # never let an earlier run's output count
        if name in self.selected and not self.offline:
            mode = self.args.osv_cli
            if mode == "never":
                self.status(name, "skipped", "--osv-cli never")
                return
            if mode == "auto" and self.mcp_status == "used":
                self.status(name, "skipped", "the osv-scanner MCP scan ran (Step 4.1)")
                return
        exe = C.find_tool("osv-scanner")
        if not self.gate(name, bool(self.manifests), exe, sends_names=True):
            return
        empty = self.raw / "osv-scanner-empty.toml"
        empty.write_text("", encoding="utf-8")
        # Hard rule 0: scan the staged copy of manifests and lockfiles, never the project, and keep the
        # "directory" plugins (vendored-code hashing, git commit lookups) off.
        scan_path = self.scan_path
        if scan_path is None:
            self.status(name, "skipped", "no staged scan input (raw/scan-input/); rerun detect_inventory.py")
            return
        args = ["scan", "source", "-r", "--format", "json", "--output-file", str(cli_out), "--config", str(empty),
                "--no-call-analysis=all", "--allow-no-lockfiles", "--x-disable-plugins=directory", str(scan_path)]
        why = {"not-configured": "no osv-scanner MCP server is configured, so the CLI ran instead (Step 4.1)",
               "failed": "the MCP scan failed, so the CLI ran instead (Step 4.1)",
               "skipped-go": "Go modules are present, so the CLI ran with --no-call-analysis=all instead of the MCP scan "
                             "(open question 13)"}.get(self.mcp_status, "run with --osv-cli always")
        st = self.status(name, "ran", why, version=self.version_of(exe))
        try:
            r = self.run_tool(exe, args, cwd=self.work, timeout=max(self.timeout, 900))
        except ToolError as e:
            st.update(status="failed", reason=str(e))
            return
        log = self.save("osv-scanner.stderr.txt", r.stderr)
        st["runs"].append({"target": ".", "command": "osv-scanner " + " ".join(args[:-1]) + " <target>",
                           "exit_code": r.returncode, "output": "osv-cli.json", "log": log})
        if r.returncode in (0, 1) and cli_out.is_file():
            try:
                data = C.read_json(cli_out)
                st["matches"] = sum(len(p.get("vulnerabilities") or []) for res in data.get("results") or []
                                    for p in res.get("packages") or [])
            except ValueError as e:
                st.update(status="failed", reason="unreadable JSON output (%s)" % e)
        elif r.returncode == 128:
            st.update(reason="no lockfiles or manifests it can read", matches=0)
        else:
            st.update(status="failed", reason="exit code %d: %s" % (r.returncode, (r.stderr or "").strip()[-300:]))

    # ---------------------------------------------------------------- npm audit
    def npm_audit(self):
        name = "npm-audit"
        locks = self.files(r"(^|/)(package-lock|npm-shrinkwrap)\.json$", "lockfile")
        exe = shutil.which("npm")
        if not self.gate(name, locks, exe, sends_names=True):
            return
        st = self.status(name, "ran", None, version=self.version_of(exe))
        for n, lock in enumerate(locks, 1):
            src = self.target / lock
            work = self.scratch(name, n)
            try:
                for f in ("package.json", src.name):
                    if (src.parent / f).is_file():
                        shutil.copyfile(src.parent / f, work / f)
                r = self.run_tool(exe, ["audit", "--json", "--package-lock-only", "--registry=https://registry.npmjs.org/"], cwd=work)
            except (ToolError, OSError) as e:
                st["runs"].append({"target": lock, "error": str(e)})
                continue
            out = self.save("%s-%d.json" % (name, n), r.stdout)
            run = {"target": lock, "command": "npm audit --json --package-lock-only --registry=https://registry.npmjs.org/",
                   "exit_code": r.returncode, "output": out}
            st["runs"].append(run)
            try:
                data = json.loads(r.stdout or "{}")
            except ValueError:
                run["error"] = "no JSON output: %s" % (r.stderr or "").strip()[-300:]
                continue
            if data.get("error"):
                run["error"] = str((data["error"] or {}).get("summary") or data["error"])[:300]
                continue
            versions = {}
            try:
                for path, meta in (C.read_json(src).get("packages") or {}).items():
                    if path and isinstance(meta, dict) and meta.get("version"):
                        versions[path] = meta["version"]
            except (OSError, ValueError):
                pass
            count = 0
            for pkg, vuln in (data.get("vulnerabilities") or {}).items():
                vers = C.dedupe([versions.get(node) for node in vuln.get("nodes") or [] if versions.get(node)]) or [None]
                for via in vuln.get("via") or []:
                    if not isinstance(via, dict) or (via.get("dependency") or via.get("name")) != pkg:
                        continue
                    ids = ghsa_ids(via.get("url"))
                    facts = {"title": via.get("title"), "severity": via.get("severity"), "url": via.get("url"),
                             "range": via.get("range"), "cwe": via.get("cwe"),
                             "cvss": (via.get("cvss") or {}).get("vectorString"), "npm_advisory": via.get("source")}
                    # npm audit lists every advisory of a package against all its vulnerable copies; keep the
                    # versions inside this advisory's range (all of them when the range can't be evaluated)
                    inside = [v for v in vers if v is None or range_contains(via.get("range"), v) is not False]
                    for v in inside or vers:
                        self.add_match(name, "npm", pkg, v, ids, lock, facts)
                        count += 1
            run["matches"] = count
        self.finish(st)

    # ---------------------------------------------------------------- pip-audit
    def pip_audit(self):
        name = "pip-audit"
        reqs = []
        for f in self.files(r"(^|/)requirements[^/]*\.txt$"):
            libs = self.libs_by_manifest.get(f) or []
            try:
                text = (self.target / f).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            odd = re.search(r"(?m)^\s*(-e\b|--editable\b|\.|/|\w+\s*@\s*\S+://|git\+)", text)
            if libs and all(lib.get("version_confidence") == "exact" for lib in libs) and not odd:
                reqs.append(f)
        exe = C.find_tool("pip-audit")
        if not self.gate(name, reqs, exe, sends_names=True):
            if not reqs and self.files(r"(^|/)requirements[^/]*\.txt$") and self.statuses[-1]["status"] == "not-applicable":
                self.statuses[-1]["reason"] = "no fully pinned requirements file (pip-audit --disable-pip needs exact versions)"
            return
        st = self.status(name, "ran", None, version=self.version_of(exe))
        for n, req in enumerate(reqs, 1):
            args = ["-f", "json", "-r", str(self.target / req), "--no-deps", "--disable-pip", "--progress-spinner", "off"]
            try:
                r = self.run_tool(exe, args, cwd=self.work)
            except ToolError as e:
                st["runs"].append({"target": req, "error": str(e)})
                continue
            out = self.save("%s-%d.json" % (name, n), r.stdout)
            run = {"target": req, "command": "pip-audit -f json -r %s --no-deps --disable-pip" % req,
                   "exit_code": r.returncode, "output": out}
            st["runs"].append(run)
            try:
                data = json.loads(r.stdout or "null")
            except ValueError:
                run["error"] = "no JSON output: %s" % (r.stderr or "").strip()[-300:]
                continue
            deps = data.get("dependencies") if isinstance(data, dict) else data
            count = 0
            for dep in deps or []:
                for vuln in dep.get("vulns") or []:
                    self.add_match(name, "PyPI", dep.get("name"), dep.get("version"),
                                   [vuln.get("id")] + list(vuln.get("aliases") or []), req,
                                   {"fixed_versions": vuln.get("fix_versions"), "description": (vuln.get("description") or "")[:500]})
                    count += 1
            run["matches"] = count
        self.finish(st)

    # ---------------------------------------------------------------- cargo audit
    def cargo_audit(self):
        name = "cargo-audit"
        locks = self.files(r"(^|/)Cargo\.lock$")
        exe, prefix = None, ["audit"]
        if locks:
            cargo = shutil.which("cargo")
            exe = cargo if cargo and self.version_of(cargo, ("audit", "--version")) else shutil.which("cargo-audit")
        if not self.gate(name, locks, exe):
            return
        st = self.status(name, "ran", None, version=self.version_of(exe, tuple(prefix + ["--version"])))
        for n, lock in enumerate(locks, 1):
            args = prefix + ["--json", "--file", str(self.target / lock)]
            try:
                r = self.run_tool(exe, args, cwd=self.work)
            except ToolError as e:
                st["runs"].append({"target": lock, "error": str(e)})
                continue
            out = self.save("%s-%d.json" % (name, n), r.stdout)
            run = {"target": lock, "command": "cargo audit --json --file %s" % lock, "exit_code": r.returncode, "output": out}
            st["runs"].append(run)
            try:
                data = json.loads(r.stdout or "{}")
            except ValueError:
                run["error"] = "no JSON output: %s" % (r.stderr or "").strip()[-300:]
                continue
            count = 0
            for v in ((data.get("vulnerabilities") or {}).get("list") or []):
                adv, pkg = v.get("advisory") or {}, v.get("package") or {}
                self.add_match(name, "crates.io", pkg.get("name"), pkg.get("version"), [adv.get("id")] + list(adv.get("aliases") or []),
                               lock, {"title": adv.get("title"), "url": adv.get("url"), "cvss": adv.get("cvss"),
                                      "fixed_versions": (v.get("versions") or {}).get("patched")})
                count += 1
            run["matches"] = count
        self.finish(st)

    # ---------------------------------------------------------------- bundle-audit
    def bundle_audit(self):
        name = "bundle-audit"
        locks = self.files(r"(^|/)Gemfile\.lock$")
        exe = shutil.which("bundle-audit") or shutil.which("bundler-audit")
        if not self.gate(name, locks, exe):
            return
        st = self.status(name, "ran", None, version=self.version_of(exe, ("version",)))
        for n, lock in enumerate(locks, 1):
            work = self.scratch(name, n)
            try:
                shutil.copyfile(self.target / lock, work / "Gemfile.lock")
                r = self.run_tool(exe, ["check", "--update", "--format", "json"], cwd=work)
            except (ToolError, OSError) as e:
                st["runs"].append({"target": lock, "error": str(e)})
                continue
            out = self.save("%s-%d.json" % (name, n), r.stdout)
            run = {"target": lock, "command": "bundle-audit check --update --format json (on a copy of %s)" % lock,
                   "exit_code": r.returncode, "output": out}
            st["runs"].append(run)
            try:
                data = json.loads(r.stdout[r.stdout.find("{"):] if "{" in (r.stdout or "") else "{}")
            except ValueError:
                run["error"] = "no JSON output: %s" % (r.stderr or "").strip()[-300:]
                continue
            count = 0
            for res in data.get("results") or []:
                if res.get("type") not in (None, "unpatched_gem"):
                    continue
                gem, adv = res.get("gem") or {}, res.get("advisory") or {}
                ids = [adv.get("id")]
                if adv.get("cve"):
                    ids.append("CVE-" + str(adv["cve"]).removeprefix("CVE-"))
                if adv.get("ghsa"):
                    ids.append("GHSA-" + str(adv["ghsa"]).removeprefix("GHSA-"))
                self.add_match(name, "RubyGems", gem.get("name"), gem.get("version"), ids, lock,
                               {"title": adv.get("title"), "url": adv.get("url"), "severity": adv.get("criticality"),
                                "fixed_versions": adv.get("patched_versions"), "cvss": adv.get("cvss_v3")})
                count += 1
            run["matches"] = count
        self.finish(st)

    # ---------------------------------------------------------------- composer audit
    def composer_audit(self):
        name = "composer-audit"
        locks = self.files(r"(^|/)composer\.lock$")
        exe = shutil.which("composer")
        if not self.gate(name, locks, exe, sends_names=True):
            return
        st = self.status(name, "ran", None, version=self.version_of(exe))
        for n, lock in enumerate(locks, 1):
            src = self.target / lock
            work = self.scratch(name, n)
            versions = {}
            try:
                data = C.read_json(src)
                for p in (data.get("packages") or []) + (data.get("packages-dev") or []):
                    if p.get("name"):
                        versions[p["name"].lower()] = str(p.get("version") or "").lstrip("v")
                cj = {}
                if (src.parent / "composer.json").is_file():
                    cj = C.read_json(src.parent / "composer.json")
                cj.pop("scripts", None)
                (cj.get("config") or {}).pop("audit", None)
                C.write_json(work / "composer.json", cj)
                shutil.copyfile(src, work / "composer.lock")
                r = self.run_tool(exe, ["audit", "--format=json", "--locked", "--no-plugins", "--no-scripts", "--no-interaction"], cwd=work)
            except (ToolError, OSError, ValueError) as e:
                st["runs"].append({"target": lock, "error": str(e)})
                continue
            out = self.save("%s-%d.json" % (name, n), r.stdout)
            run = {"target": lock, "command": "composer audit --format=json --locked --no-plugins --no-scripts (on copies)",
                   "exit_code": r.returncode, "output": out}
            st["runs"].append(run)
            try:
                result = json.loads(r.stdout[r.stdout.find("{"):] if "{" in (r.stdout or "") else "{}")
            except ValueError:
                run["error"] = "no JSON output: %s" % (r.stderr or "").strip()[-300:]
                continue
            advisories = result.get("advisories") or {}
            count = 0
            for pkg, items in (advisories.items() if isinstance(advisories, dict) else []):
                for adv in (items.values() if isinstance(items, dict) else items) or []:
                    ids = [adv.get("advisoryId"), adv.get("cve")] + [s.get("remoteId") for s in adv.get("sources") or []
                                                                    if str(s.get("remoteId", "")).startswith("GHSA-")]
                    self.add_match(name, "Packagist", pkg, versions.get(pkg.lower()), ids, lock,
                                   {"title": adv.get("title"), "url": adv.get("link"), "severity": adv.get("severity"),
                                    "range": adv.get("affectedVersions")})
                    count += 1
            run["matches"] = count
        self.finish(st)

    # ---------------------------------------------------------------- dotnet list package
    def dotnet_list(self):
        name = "dotnet-list-package"
        projects = self.files(r"\.(cs|fs|vb)proj$")
        restored = [p for p in projects if (self.target / p).parent.joinpath("obj", "project.assets.json").is_file()]
        exe = shutil.which("dotnet")
        if name in self.selected and not self.offline and projects and not restored:
            self.status(name, "skipped", "no project is restored (obj/project.assets.json); restoring would evaluate the "
                                         "project's build files, so it isn't done (Step 4.4)", applicable=projects)
            return
        if name in self.selected and not self.offline and restored and self.private_nuget:
            self.status(name, "skipped", "a private NuGet feed is configured (%s); dotnet would call it with the repository's "
                                         "credentials" % ", ".join(self.private_nuget), applicable=restored)
            return
        if not self.gate(name, restored, exe):
            return
        st = self.status(name, "ran", None, version=self.version_of(exe))
        for n, proj in enumerate(restored, 1):
            args = ["list", str(self.target / proj), "package", "--vulnerable", "--include-transitive", "--format", "json"]
            try:
                r = self.run_tool(exe, args, cwd=self.work)
            except ToolError as e:
                st["runs"].append({"target": proj, "error": str(e)})
                continue
            out = self.save("%s-%d.json" % (name, n), r.stdout)
            run = {"target": proj, "command": "dotnet list %s package --vulnerable --include-transitive --format json" % proj,
                   "exit_code": r.returncode, "output": out}
            st["runs"].append(run)
            try:
                data = json.loads(r.stdout or "{}")
            except ValueError:
                run["error"] = "no JSON output (needs .NET SDK 7.0.200 or later): %s" % ((r.stdout or r.stderr or "").strip()[-300:])
                continue
            count = 0
            for project in data.get("projects") or []:
                for fw in project.get("frameworks") or []:
                    for pkg in (fw.get("topLevelPackages") or []) + (fw.get("transitivePackages") or []):
                        for vuln in pkg.get("vulnerabilities") or []:
                            self.add_match(name, "NuGet", pkg.get("id"), pkg.get("resolvedVersion"),
                                           ghsa_ids(vuln.get("advisoryurl")), proj,
                                           {"severity": vuln.get("severity"), "url": vuln.get("advisoryurl")})
                            count += 1
            run["matches"] = count
        self.finish(st)

    # ---------------------------------------------------------------- trivy
    def trivy(self):
        name = "trivy"
        exe = C.find_tool("trivy")
        if not self.gate(name, bool(self.manifests), exe):
            return
        if self.scan_path is None:
            self.status(name, "skipped", "no staged scan input (raw/scan-input/); rerun detect_inventory.py")
            return
        st = self.status(name, "ran", None, version=self.version_of(exe))
        empty = self.work / "empty.trivyignore"
        empty.write_text("", encoding="utf-8")
        out_file = self.work / "trivy.json"
        args = ["fs", "--scanners", "vuln", "--format", "json", "--output", str(out_file), "--offline-scan",
                "--ignorefile", str(empty), "--quiet", str(self.scan_path)]
        try:
            r = self.run_tool(exe, args, cwd=self.work, timeout=max(self.timeout, 900))
        except ToolError as e:
            st.update(status="failed", reason=str(e))
            return
        run = {"target": ".", "command": "trivy fs --scanners vuln --format json --offline-scan --ignorefile <empty> <target>",
               "exit_code": r.returncode, "output": C.posix(out_file.relative_to(self.raw))}
        st["runs"].append(run)
        try:
            data = C.read_json(out_file)
        except (OSError, ValueError):
            st.update(status="failed", reason="exit code %d: %s" % (r.returncode, (r.stderr or "").strip()[-300:]))
            return
        count = 0
        for res in data.get("Results") or []:
            target = C.posix(res.get("Target") or "")
            eco = TRIVY_ECOSYSTEM.get(res.get("Type"))
            if not eco or under_excluded(target, self.excluded):
                continue
            for v in res.get("Vulnerabilities") or []:
                self.add_match(name, eco, v.get("PkgName"), v.get("InstalledVersion"),
                               [v.get("VulnerabilityID")] + list(v.get("VendorIDs") or []), target,
                               {"title": v.get("Title"), "severity": (v.get("Severity") or "").lower(), "url": v.get("PrimaryURL"),
                                "fixed_versions": [x.strip() for x in (v.get("FixedVersion") or "").split(",") if x.strip()]})
                count += 1
        run["matches"] = count
        self.finish(st)

    def govulncheck(self):
        if "govulncheck" in self.selected:
            mods = self.files(r"(^|/)go\.mod$")
            self.status("govulncheck", "skipped" if mods else "not-applicable",
                        "never run: it loads Go packages through the Go toolchain (open question 13); use the manual "
                        "reachability check (Step 4.7)" if mods else "no go.mod")

    def finish(self, st: dict) -> None:
        st["matches"] = sum(r.get("matches", 0) for r in st["runs"])
        errs = [r for r in st["runs"] if r.get("error")]
        if errs and len(errs) == len(st["runs"]):
            st["status"] = "failed"
            st["reason"] = "; ".join("%s: %s" % (r["target"], r["error"]) for r in errs)[:600]
        elif errs:
            st["reason"] = "failed for " + "; ".join("%s: %s" % (r["target"], r["error"]) for r in errs)[:600]

    def run(self) -> None:
        self.work.mkdir(parents=True, exist_ok=True)
        self.osv_cli()
        for step in (self.npm_audit, self.pip_audit, self.cargo_audit, self.bundle_audit, self.composer_audit,
                     self.dotnet_list, self.trivy, self.govulncheck):
            try:
                step()
            except Exception as e:   # one broken scanner never stops the others (spec §9)
                self.errors.append("%s crashed: %s: %s" % (step.__name__, type(e).__name__, e))
        for st in self.statuses:
            if st["status"] == "failed":
                self.errors.append("%s failed: %s" % (st["name"], st["reason"]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the installed dependency scanners read-only and normalize their output.")
    ap.add_argument("--out", required=True, help="output directory (holds raw/inventory.json)")
    ap.add_argument("--mcp-status", choices=MCP_STATUSES, help="what happened to the osv-scanner MCP scan")
    ap.add_argument("--mcp-version", help="osv-scanner MCP server version, from its initialize response")
    ap.add_argument("--mcp-error", help="the MCP tool's error, with --mcp-status failed")
    ap.add_argument("--osv-cli", choices=("auto", "always", "never"), default="auto")
    ap.add_argument("--only", help="comma-separated scanner names to run")
    ap.add_argument("--skip", help="comma-separated scanner names to leave out")
    ap.add_argument("--timeout", type=int, default=300, help="seconds per scanner run (osv-scanner and trivy get at least 900)")
    args = ap.parse_args(argv)
    out = Path(args.out)
    inv_path = C.raw_dir(out) / "inventory.json"
    if not inv_path.is_file():
        print("error: %s not found; run detect_inventory.py first" % inv_path, file=sys.stderr)
        return 2
    runner = Runner(out, C.read_json(inv_path), args)
    runner.run()
    mcp = {"name": "osv-scanner-mcp", "status": runner.mcp_status, "version": args.mcp_version,
           "reason": C.redact_text(args.mcp_error)[:500] if args.mcp_error else None}
    if mcp["status"] == "failed":
        runner.errors.insert(0, "osv-scanner MCP scan failed: %s" % (mcp["reason"] or "no details"))
    elif mcp["status"] == "skipped-private":
        runner.errors.insert(0, "osv-scanner MCP scan not called: %s; it would send them to OSV.dev and deps.dev (Step 4.1)"
                             % (runner.private_reason or "the inventory has private packages"))
    data = {"tool": {"name": "run_scanners.py", "version": C.TOOL_VERSION}, "generated_at": C.now_iso(),
            "mcp": mcp, "scanners": runner.statuses, "errors": runner.errors}
    C.write_json(C.raw_dir(out) / "scanners.json", data)
    C.write_json(C.raw_dir(out) / "scanner-results.json", {"generated_at": data["generated_at"], "matches": runner.matches})

    print("wrote %s" % (C.raw_dir(out) / "scanners.json"))
    print("osv-scanner MCP: %s" % mcp["status"])
    for st in runner.statuses:
        extra = (" (%d matches)" % st["matches"]) if st.get("matches") is not None and st["status"] == "ran" else ""
        print("  %-20s %-15s%s%s" % (st["name"], st["status"], (st.get("version") or "") and "v" + st["version"], extra)
              + ("  - " + st["reason"] if st.get("reason") else ""))
    for e in runner.errors:
        print("error: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
