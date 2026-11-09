#!/usr/bin/env python3
"""Step 3 of the dependency audit: support status for every runtime and library.

Usage:
    python check_support.py --out <dir> [--unmaintained-months N] [--offline] [--workers N]

Reads <out>/raw/inventory.json (from detect_inventory.py) and writes <out>/raw/support.json, plus the
endoflife.date product files it used under <out>/raw/eol/ and any support-policy pages under
<out>/raw/policies/. Frameworks take the support object of their library (build_report.py copies it).

Sources, in order of trust (spec Step 3):
  1. endoflife.date API, for runtimes and for packages mapped in rules/support_sources.yaml
  2. support-policy pages listed in that file (saved for the agent to read; status is not changed here)
  3. registry metadata: npm deprecated, PyPI yanked and "Inactive" classifier, Packagist abandoned,
     NuGet deprecation, RubyGems/crates.io yanked, Go deprecated or retracted, pub.dev discontinued or
     retracted, CocoaPods deprecated
  4. repository signals (GitHub/GitLab archived flag plus the date of the last release), for
     "unmaintained" only, checked for direct dependencies

No network (spec §9): unless --offline is set, it first sends one plain request to api.osv.dev and
endoflife.date. When neither answers, it writes nothing and exits 3, so the audit restarts offline.

Hard rule 2: every status other than "unknown", and every date, comes from a response fetched in this
run. Hard rule 5: private packages are never looked up; only names and versions of public packages are
sent. A library whose registry check ran and came back clean is "supported" (open question 6);
"unknown" means no check could run.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import fnmatch
import html
import json
import os
import re
import sys
import threading
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

ECO_KEY = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "go", "crates.io": "cargo", "RubyGems": "gem",
           "Packagist": "composer", "NuGet": "nuget", "Pub": "pub", "CocoaPods": "cocoapods", "SwiftURL": "swift"}
SOURCE_NAME = {"npm": "npm registry", "PyPI": "PyPI JSON API", "Packagist": "Packagist", "NuGet": "nuget.org registration API",
               "RubyGems": "rubygems.org API", "crates.io": "crates.io index", "Go": "Go module proxy",
               "Maven": "Maven Central", "Pub": "pub.dev API", "CocoaPods": "CocoaPods trunk", "SwiftURL": "GitHub API"}
STATUS_RANK = {"end-of-life": 0, "deprecated": 1, "unmaintained": 2, "security-only": 3, "supported": 4, "unknown": 5}
NETWORK_PROBE_HOSTS = ("api.osv.dev", "endoflife.date")


def quote_msg(text, limit=300) -> str:
    """Publisher-written text (deprecation messages and the like) is data (hard rule 6): flatten it,
    strip markup, cut it to `limit` characters and keep it inside quotes."""
    t = re.sub(r"<[^>]{0,200}>", " ", html.unescape(str(text or "")))
    t = C.redact_text(re.sub(r"\s+", " ", t)).strip()
    return (t[:limit] + "…") if len(t) > limit else t


def parse_date(value) -> dt.date | None:
    if not value or not isinstance(value, str):
        return None
    m = re.match(r"(\d{4})-?(\d{2})-?(\d{2})", value)
    if not m:
        return None
    try:
        return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def months_before(day: dt.date, months: int) -> dt.date:
    y, m = divmod(day.year * 12 + (day.month - 1) - months, 12)
    return dt.date(y, m + 1, min(day.day, 28))


def stable(versions):
    return [v for v in versions if v and not C.is_prerelease(v)]


def max_version(versions):
    vs = [v for v in versions if v]
    return max(vs, key=C.version_sort_key) if vs else None


def repo_slug(url: str | None):
    """('github'|'gitlab', 'owner/repo') for a public GitHub or GitLab repository URL, else None."""
    if not url:
        return None
    m = re.search(r"(github\.com|gitlab\.com)[/:]([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?(?:[/#?]|$)", str(url))
    if not m:
        return None
    return ("github" if m.group(1) == "github.com" else "gitlab"), "%s/%s" % (m.group(2), m.group(3))


def nuget_norm(v: str) -> str:
    v = (v or "").split("+")[0].strip().lower()
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(-.*)?$", v)
    if not m:
        return v
    parts = [int(x) if x else 0 for x in m.groups()[:4]]
    out = "%d.%d.%d" % tuple(parts[:3])
    if parts[3]:
        out += ".%d" % parts[3]
    return out + (m.group(5) or "")


def go_escape(path: str) -> str:
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


class Net:
    """HTTP with a per-run cache, a list of unreachable hosts (so one dead host costs one timeout, not
    hundreds) and per-host counters for the coverage section."""

    def __init__(self):
        self.cache: dict[str, object] = {}
        self.down: dict[str, str] = {}
        self.lock = threading.Lock()
        self.ok_hosts: dict[str, int] = {}
        self.errors: list[str] = []

    def _host(self, url):
        return urllib.parse.urlsplit(url).hostname or ""

    def get(self, url, kind="json", headers=None, retries=2, timeout=25):
        key = kind + " " + url + " " + json.dumps(headers or {}, sort_keys=True)
        with self.lock:
            if key in self.cache:
                cached = self.cache[key]
                if isinstance(cached, C.FetchError):
                    raise cached
                return cached
            host = self._host(url)
            if host in self.down:
                raise C.FetchError(url, "host unreachable earlier in this run (%s)" % self.down[host])
        try:
            if kind == "json":
                value = C.get_json(url, headers=headers, retries=retries, timeout=timeout)
            else:
                value = C.get_text(url, headers=headers, retries=retries, timeout=timeout)
        except C.FetchError as e:
            with self.lock:
                if e.status is None and "offline" not in e.message:
                    if host not in self.down:
                        self.down[host] = e.message
                        self.errors.append("support check: %s unreachable (%s); lookups to it were skipped" % (host, e.message))
                self.cache[key] = e
            raise
        with self.lock:
            self.cache[key] = value
            self.ok_hosts[host] = self.ok_hosts.get(host, 0) + 1
        return value


class Registry:
    """Result of one registry lookup."""

    def __init__(self, source):
        self.source = source
        self.ran = False                  # the lookup answered
        self.found = True                 # the package/version exists there
        self.deprecated = None            # reason text when deprecated, yanked, abandoned, retracted, ...
        self.alternate = None             # {"id": ..., "range": ...}
        self.inactive = None              # maintainer-declared inactivity (PyPI classifier)
        self.latest = None                # newest stable version
        self.last_release = None          # dt.date of the newest release, when known
        self.last_release_is_bound = False  # last_release is only an upper bound (npm "modified")
        self.repository = None
        self.newer_major_path = None      # Go: the /vN+1 module path when it exists
        self.note = None


PRODUCT_LABEL = {"dotnet": ".NET", "dotnetfx": ".NET Framework", "nodejs": "Node.js", "jquery": "jQuery", "jquery-ui": "jQuery UI",
                 "angularjs": "AngularJS", "nextjs": "Next.js", "log4j": "Log4j", "hibernate-orm": "Hibernate ORM",
                 "tomcat": "Apache Tomcat", "emberjs": "Ember.js", "numpy": "NumPy", "cakephp": "CakePHP", "nestjs": "NestJS",
                 "quarkus-framework": "Quarkus", "apache-struts": "Apache Struts", "eclipse-jetty": "Eclipse Jetty",
                 "react-native": "React Native", "spring-boot": "Spring Boot", "spring-framework": "Spring Framework",
                 "spring-security": "Spring Security", "eclipse-temurin": "Eclipse Temurin", "alpine-linux": "Alpine Linux"}


def product_label(product: str) -> str:
    return PRODUCT_LABEL.get(product) or " ".join(w.capitalize() for w in product.split("-"))


class SupportChecker:
    def __init__(self, inventory, opts, out: Path):
        self.inv = inventory
        self.opts = opts
        self.out = out
        self.net = Net()
        self.today = C.today()
        self.stale_before = months_before(self.today, opts.unmaintained_months)
        self.rules = C.load_rules("support_sources") or {}
        self.eol_cache: dict[str, object] = {}
        self.eol_lock = threading.Lock()
        self.gaps: list[str] = []
        self.errors: list[str] = []
        self.sources_used: set[str] = set()
        self.github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.github_limited = False
        self.repo_checks = {"done": 0, "skipped_rate_limit": 0}
        self.policies_saved: list[dict] = []
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ endoflife.date
    def eol_product(self, product):
        with self.eol_lock:
            if product in self.eol_cache:
                return self.eol_cache[product]
        try:
            data = self.net.get("https://endoflife.date/api/%s.json" % urllib.parse.quote(product))
            if not isinstance(data, list):
                raise C.FetchError(product, "unexpected response")
            eol_dir = self.out / "raw" / "eol"
            eol_dir.mkdir(parents=True, exist_ok=True)
            C.write_json(eol_dir / ("%s.json" % product), data)
            self.sources_used.add("endoflife.date API")
        except C.FetchError as e:
            data = e
        with self.eol_lock:
            self.eol_cache[product] = data
        return data

    @staticmethod
    def match_cycle(cycles, version):
        """The cycle whose name is the longest dotted prefix of `version` ("3.2.25" -> "3.2", "6.0" -> "6")."""
        v = str(version).strip().lower()
        best = None
        for c in cycles:
            name = str(c.get("cycle", "")).lower()
            if not name:
                continue
            if v == name or v.startswith(name + ".") or v.startswith(name + "-"):
                if best is None or len(name) > len(str(best["cycle"])):
                    best = c
        if best is None:
            stripped = re.sub(r"(\.0)+$", "", v)
            if stripped != v:
                return SupportChecker.match_cycle(cycles, stripped)
        return best

    def newest_cycle(self, cycles):
        released = [c for c in cycles if not (parse_date(c.get("releaseDate")) and parse_date(c.get("releaseDate")) > self.today)]
        if not released:
            return None
        return max(released, key=lambda c: C.version_sort_key(str(c.get("latest") or c.get("cycle"))))

    def eol_status(self, product, version, label, package=None):
        """Support from endoflife.date for `version`, or (None, note) when the product has no matching
        cycle or couldn't be fetched. `label` names the product; `package` is the library name when it
        differs from the product (\"Spring Boot 2.5 (org.springframework.boot:spring-boot-starter-web)\")."""
        cycles = self.eol_product(product)
        if isinstance(cycles, C.FetchError):
            return None, "endoflife.date lookup failed (%s)" % cycles.message
        cyc = self.match_cycle(cycles, version)
        newest = self.newest_cycle(cycles)
        newer_major = None
        if newest is not None:
            newer_major = (C.major_of(str(newest.get("latest") or newest.get("cycle"))) or 0) > (C.major_of(version) or 0)
        if cyc is None:
            return None, "endoflife.date (%s) has no release cycle matching %s" % (product, version)
        name = "%s %s" % (label, cyc["cycle"])
        if package and package.lower() not in (label.lower(), product.lower()):
            name += " (%s)" % package
        eol, support, ext = cyc.get("eol"), cyc.get("support"), cyc.get("extendedSupport")
        eol_date, support_date, ext_date = parse_date(eol), parse_date(support), parse_date(ext)
        src = "endoflife.date API (%s)" % product
        if eol is True or (eol_date and eol_date <= self.today):
            if eol_date:
                reason = "%s reached end of life on %s." % (name, eol_date.isoformat())
            else:
                reason = "%s is marked end-of-life by endoflife.date (no date published)." % name
            if ext_date and ext_date > self.today:
                reason += " endoflife.date lists extended support until %s." % ext_date.isoformat()
            status = "end-of-life"
        elif support_date and support_date <= self.today or support is False:
            status = "security-only"
            ended = ("ended on %s" % support_date.isoformat()) if support_date else "has ended"
            until = ("until %s" % eol_date.isoformat()) if eol_date else "with no end-of-life date published"
            reason = "%s: active support %s; security fixes only, %s." % (name, ended, until)
        else:
            status = "supported"
            if eol_date:
                reason = "%s is supported until %s." % (name, eol_date.isoformat())
            elif product == "dotnetfx":
                reason = "%s has no published end-of-life date; its support follows the Windows lifecycle." % name
            else:
                reason = "%s is supported; no end-of-life date is published." % name
        return {"status": status, "eol_date": eol_date.isoformat() if eol_date else None, "reason": reason,
                "source": src, "newer_major_available": newer_major, "cycle": str(cyc["cycle"]), "product": product}, None

    def eol_product_for(self, lib):
        key = ECO_KEY.get(lib["ecosystem"])
        name = C.normalize_pypi(lib["name"]) if key == "pypi" else lib["name"]
        for entry in self.rules.get("packages") or []:
            for pat in (entry.get("packages") or {}).get(key) or []:
                if fnmatch.fnmatchcase(name.lower(), str(pat).lower()):
                    return entry["endoflife_product"]
        return None

    # ------------------------------------------------------------------ repository signals
    def repo_status(self, url):
        """(archived: bool|None, where-or-error, last push date). One GitHub or GitLab API request,
        sending only the public repository name."""
        slug = repo_slug(url)
        if not slug:
            return None, None, None
        kind, path = slug
        if kind == "github":
            if self.github_limited:
                with self.lock:
                    self.repo_checks["skipped_rate_limit"] += 1
                return None, "GitHub rate limit reached", None
            headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
            if self.github_token:
                headers["Authorization"] = "Bearer " + self.github_token
            try:
                d = self.net.get("https://api.github.com/repos/%s" % path, headers=headers, retries=0)
            except C.FetchError as e:
                if e.status in (403, 429):
                    self.github_limited = True
                    return None, "GitHub rate limit reached", None
                return None, "GitHub lookup failed (%s)" % e.message, None
            self.sources_used.add("GitHub API")
            pushed = parse_date(d.get("pushed_at"))
        else:
            try:
                d = self.net.get("https://gitlab.com/api/v4/projects/%s" % urllib.parse.quote(path, safe=""), retries=0)
            except C.FetchError as e:
                return None, "GitLab lookup failed (%s)" % e.message, None
            self.sources_used.add("GitLab API")
            pushed = parse_date(d.get("last_activity_at"))
        with self.lock:
            self.repo_checks["done"] += 1
        return bool(d.get("archived")), "%s.com/%s" % (kind, path), pushed

    # ------------------------------------------------------------------ registries
    def check_registry(self, lib, version, deep):
        eco = lib["ecosystem"]
        fn = getattr(self, "reg_" + {"crates.io": "cargo"}.get(eco, eco.lower()), None)
        if fn is None:
            return None
        r = Registry(SOURCE_NAME.get(eco, eco))
        try:
            fn(r, lib["name"], version, deep)
            r.ran = True
            self.sources_used.add(r.source)
        except C.FetchError as e:
            if e.status == 404:
                r.ran, r.found = True, False
                r.note = "%s has no record of %s" % (r.source, lib["name"])
                self.sources_used.add(r.source)
            else:
                r.note = "%s lookup failed (%s)" % (r.source, e.message)
        except (KeyError, TypeError, ValueError, IndexError, AttributeError) as e:
            r.note = "%s returned data this script couldn't read (%s: %s)" % (r.source, type(e).__name__, e)
        return r

    def reg_npm(self, r, name, version, deep):
        enc = urllib.parse.quote(name, safe="@")
        if version:
            try:
                doc = self.net.get("https://registry.npmjs.org/%s/%s" % (enc, urllib.parse.quote(version, safe="")))
                if doc.get("deprecated"):
                    r.deprecated = 'The npm registry marks %s@%s deprecated: "%s"' % (name, version, quote_msg(doc["deprecated"]))
                repo = doc.get("repository")
                r.repository = repo.get("url") if isinstance(repo, dict) else repo
            except C.FetchError as e:
                if e.status != 404:
                    raise
                r.found = False
                r.note = "the npm registry has no version %s of %s (unpublished?)" % (version, name)
        if deep:
            # abbreviated document: dist-tags and "modified", which bounds the date of the last release
            doc = self.net.get("https://registry.npmjs.org/%s" % enc, headers={"Accept": "application/vnd.npm.install-v1+json"})
            r.latest = (doc.get("dist-tags") or {}).get("latest")
            r.last_release = parse_date(doc.get("modified"))
            r.last_release_is_bound = True
        else:
            tags = self.net.get("https://registry.npmjs.org/-/package/%s/dist-tags" % enc)
            r.latest = tags.get("latest")

    def reg_pypi(self, r, name, version, deep):
        d = self.net.get("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name))
        info = d.get("info") or {}
        r.latest = info.get("version")
        uploads = [parse_date(f.get("upload_time_iso_8601") or f.get("upload_time")) for f in d.get("urls") or []]
        uploads = [u for u in uploads if u]
        r.last_release = max(uploads) if uploads else None
        if "Development Status :: 7 - Inactive" in (info.get("classifiers") or []):
            r.inactive = "the latest release on PyPI is classified \"Development Status :: 7 - Inactive\""
        urls = info.get("project_urls") or {}
        r.repository = next((u for u in urls.values() if repo_slug(u)), None) or info.get("home_page")
        if version:
            releases = d.get("releases")
            files = None
            if isinstance(releases, dict):
                files = releases.get(version)
                if files is None:
                    key = next((k for k in releases if C.compare_versions(k, version) == 0), None)
                    files = releases.get(key) if key else None
            if files is None:
                try:
                    vd = self.net.get("https://pypi.org/pypi/%s/%s/json" % (urllib.parse.quote(name), urllib.parse.quote(version)))
                    files = [{"yanked": (vd.get("info") or {}).get("yanked"), "yanked_reason": (vd.get("info") or {}).get("yanked_reason")}]
                except C.FetchError as e:
                    if e.status != 404:
                        raise
                    r.found = False
                    r.note = "PyPI has no release %s of %s" % (version, name)
                    return
            if files and all(f.get("yanked") for f in files):
                why = next((f.get("yanked_reason") for f in files if f.get("yanked_reason")), None)
                r.deprecated = "PyPI marks %s %s yanked%s" % (name, version, (': "%s"' % quote_msg(why)) if why else "")

    def reg_packagist(self, r, name, version, deep):
        d = self.net.get("https://repo.packagist.org/p2/%s.json" % name.lower())
        entries = (d.get("packages") or {}).get(name.lower()) or []
        if d.get("minified"):
            expanded, prev = [], {}
            for e in entries:
                cur = dict(prev)
                for k, v in e.items():
                    if v == "__unset":
                        cur.pop(k, None)
                    else:
                        cur[k] = v
                expanded.append(cur)
                prev = cur
            entries = expanded
        if not entries:
            raise C.FetchError(name, "no versions", 404)
        abandoned = entries[0].get("abandoned")
        if abandoned:
            repl = abandoned if isinstance(abandoned, str) else None
            r.deprecated = "Packagist marks %s abandoned%s" % (name, ("; suggested replacement: %s" % repl) if repl else "")
            if repl:
                r.alternate = {"id": repl}
        stable_entries = [e for e in entries if e.get("version") and not C.is_prerelease(e["version"])]
        newest = max(stable_entries, key=lambda e: C.version_sort_key(e["version"])) if stable_entries else None
        if newest:
            r.latest = re.sub(r"^v(?=\d)", "", newest["version"])
            r.last_release = parse_date(newest.get("time"))
        src = entries[0].get("source") or {}
        r.repository = src.get("url") if isinstance(src, dict) else None
        if version and not any(C.compare_versions(re.sub(r"^v(?=\d)", "", e.get("version", "")), version) == 0 for e in entries):
            r.found = False
            r.note = "Packagist lists no version %s of %s" % (version, name)

    def reg_nuget(self, r, name, version, deep):
        lid = name.lower()
        idx = self.net.get("https://api.nuget.org/v3/registration5-gz-semver2/%s/index.json" % urllib.parse.quote(lid))
        target = nuget_norm(version) if version else None
        pages = idx.get("items") or []
        entry, seen = None, []
        for i, page in enumerate(pages):
            lower, upper = page.get("lower", ""), page.get("upper", "")
            holds = target is not None and C.compare_versions(lower, target) <= 0 <= C.compare_versions(upper, target)
            if not holds and i != len(pages) - 1:
                continue  # only the page holding our version and the last page (for the newest version)
            items = page.get("items")
            if items is None:
                items = (self.net.get(page["@id"]) or {}).get("items") or []
            for it in items:
                ce = it.get("catalogEntry") or {}
                seen.append(ce)
                if target is not None and nuget_norm(ce.get("version", "")) == target:
                    entry = ce
        listed = [ce for ce in seen if ce.get("listed", True) is not False and not C.is_prerelease(ce.get("version", ""))]
        if listed:
            newest = max(listed, key=lambda ce: C.version_sort_key(ce["version"]))
            r.latest = newest["version"]
            pub = parse_date(newest.get("published"))
            r.last_release = pub if pub and pub.year > 1900 else None
        if target is not None and entry is None:
            r.found = False
            r.note = "nuget.org has no version %s of %s" % (version, name)
            return
        if entry is not None:
            r.repository = entry.get("projectUrl")
            dep = entry.get("deprecation")
            if dep:
                reasons = ", ".join(dep.get("reasons") or []) or "no reason given"
                msg = quote_msg(dep.get("message")) if dep.get("message") else ""
                r.deprecated = "nuget.org marks %s %s deprecated (%s)%s" % (name, version, reasons, (': "%s"' % msg) if msg else "")
                alt = dep.get("alternatePackage") or {}
                if alt.get("id"):
                    r.alternate = {"id": alt["id"], "range": alt.get("range")}

    def reg_rubygems(self, r, name, version, deep):
        versions = self.net.get("https://rubygems.org/api/v1/versions/%s.json" % urllib.parse.quote(name))
        numbers = [v.get("number") for v in versions]
        rel = [v for v in versions if not v.get("prerelease")]
        if rel:
            newest = max(rel, key=lambda v: C.version_sort_key(v["number"]))
            r.latest = newest["number"]
            r.last_release = parse_date(newest.get("created_at"))
        if version and version not in numbers:
            r.deprecated = "rubygems.org no longer lists %s %s (yanked)" % (name, version)
        if deep:
            try:
                g = self.net.get("https://rubygems.org/api/v1/gems/%s.json" % urllib.parse.quote(name))
                r.repository = g.get("source_code_uri") or g.get("homepage_uri")
            except C.FetchError:
                pass

    def reg_cargo(self, r, name, version, deep):
        n = name.lower()
        path = {1: "1/%s" % n, 2: "2/%s" % n, 3: "3/%s/%s" % (n[0], n)}.get(len(n), "%s/%s/%s" % (n[:2], n[2:4], n))
        text = self.net.get("https://index.crates.io/%s" % path, kind="text")
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        good = [x for x in rows if not x.get("yanked") and not C.is_prerelease(x.get("vers", ""))]
        if good:
            newest = max(good, key=lambda x: C.version_sort_key(x["vers"]))
            r.latest = newest["vers"]
            r.last_release = parse_date(newest.get("pubtime"))
        if version:
            mine = next((x for x in rows if x.get("vers") == version), None)
            if mine is None:
                r.found = False
                r.note = "the crates.io index has no version %s of %s" % (version, name)
            elif mine.get("yanked"):
                r.deprecated = "crates.io marks %s %s yanked" % (name, version)
        if deep and r.last_release and r.last_release < self.stale_before:
            try:
                d = self.net.get("https://crates.io/api/v1/crates/%s" % urllib.parse.quote(n))
                r.repository = (d.get("crate") or {}).get("repository")
            except C.FetchError:
                pass

    def reg_go(self, r, name, version, deep):
        base = "https://proxy.golang.org/%s" % go_escape(name)
        latest = self.net.get(base + "/@latest")
        r.latest = str(latest.get("Version", "")).lstrip("v") or None
        r.last_release = parse_date(latest.get("Time"))
        if repo_slug("https://" + name):
            r.repository = "https://" + "/".join(name.split("/")[:3])
        if latest.get("Version"):
            mod = self.net.get(base + "/@v/%s.mod" % latest["Version"], kind="text")
            why = self.go_deprecated(mod)
            if why:
                r.deprecated = 'The module is deprecated: "%s"' % quote_msg(why)
            if version and not r.deprecated:
                why = self.go_retracted(mod, version)
                if why is not None:
                    r.deprecated = "The module's go.mod retracts %s%s" % (version, (': "%s"' % quote_msg(why)) if why else "")
        # a newer major version lives at a new module path (/v2, /v3, ...)
        m = re.match(r"^(.*?)/v(\d+)$", name)
        stem, major = (m.group(1), int(m.group(2))) if m else (name, 1)
        try:
            nxt = self.net.get("https://proxy.golang.org/%s/v%d/@latest" % (go_escape(stem), major + 1), retries=0)
            r.newer_major_path = "%s/v%d" % (stem, major + 1) if nxt.get("Version") else None
        except C.FetchError:
            r.newer_major_path = None

    @staticmethod
    def go_deprecated(mod_text):
        """The text of a "// Deprecated:" comment on the module directive or in the comment block
        directly above it (the Go convention), else None."""
        lines = mod_text.splitlines()
        idx = next((i for i, l in enumerate(lines) if re.match(r"^\s*module\s", l)), None)
        if idx is None:
            return None
        m = re.search(r"//\s*Deprecated:\s*(.+)$", lines[idx])
        if m:
            return m.group(1).strip()
        j = idx - 1
        while j >= 0 and lines[j].strip().startswith("//"):
            m = re.match(r"^\s*//\s*Deprecated:\s*(.+)$", lines[j])
            if m:
                return m.group(1).strip()
            j -= 1
        return None

    @staticmethod
    def go_retracted(mod_text, version):
        """Rationale text ('' when none) if `version` is retracted by this go.mod, else None."""
        v = version.lstrip("v")
        lines = mod_text.splitlines()
        block = False
        for line in lines:
            s = line.strip()
            if s.startswith("retract ("):
                block = True
                continue
            if block and s == ")":
                block = False
                continue
            body = s[len("retract"):].strip() if s.startswith("retract") and not block else (s if block else None)
            if not body:
                continue
            spec, _, comment = body.partition("//")
            spec = spec.strip()
            m = re.match(r"^\[\s*v?([^,\s]+)\s*,\s*v?([^\]\s]+)\s*\]$", spec)
            if m:
                if C.compare_versions(m.group(1), v) <= 0 <= C.compare_versions(m.group(2), v):
                    return comment.strip()
            elif spec.lstrip("v") == v:
                return comment.strip()
        return None

    def reg_maven(self, r, name, version, deep):
        g, _, a = name.partition(":")
        path = "%s/%s" % (g.replace(".", "/"), a)
        hosts = ["https://repo1.maven.org/maven2"]
        if g.startswith(("androidx.", "com.android", "com.google.android")):
            hosts.insert(0, "https://dl.google.com/android/maven2")
        text, base = None, None
        for h in hosts:
            try:
                text = self.net.get("%s/%s/maven-metadata.xml" % (h, path), kind="text")
                base = h
                break
            except C.FetchError as e:
                if e.status != 404:
                    raise
        if text is None:
            raise C.FetchError(name, "not found", 404)
        if "google.com" in base:
            r.source = "Google Maven repository"
        versions = re.findall(r"<version>([^<]+)</version>", text)
        r.latest = max_version(stable(versions))
        m = re.search(r"<lastUpdated>(\d{8})", text)
        r.last_release = parse_date(m.group(1)) if m else None
        if version and versions and version not in versions:
            r.found = False
            r.note = "%s lists no version %s of %s" % (r.source, version, name)
        if deep and r.last_release and r.last_release < self.stale_before and version:
            try:
                pom = self.net.get("%s/%s/%s/%s-%s.pom" % (base, path, version, a, version), kind="text")
                mm = re.search(r"<scm>.*?<url>([^<]+)</url>", pom, re.S) or re.search(r"<url>([^<]+)</url>", pom)
                r.repository = mm.group(1).strip() if mm else None
            except C.FetchError:
                pass

    def reg_pub(self, r, name, version, deep):
        d = self.net.get("https://pub.dev/api/packages/%s" % urllib.parse.quote(name))
        if d.get("isDiscontinued"):
            repl = d.get("replacedBy")
            r.deprecated = "pub.dev marks %s discontinued%s" % (name, ("; replaced by %s" % repl) if repl else "")
            if repl:
                r.alternate = {"id": repl}
        latest = d.get("latest") or {}
        r.latest = latest.get("version")
        r.last_release = parse_date(latest.get("published"))
        pubspec = latest.get("pubspec") or {}
        r.repository = pubspec.get("repository") or pubspec.get("homepage")
        if version:
            mine = next((v for v in d.get("versions") or [] if v.get("version") == version), None)
            if mine is None:
                r.found = False
                r.note = "pub.dev has no version %s of %s" % (version, name)
            elif mine.get("retracted") and not r.deprecated:
                r.deprecated = "pub.dev marks %s %s retracted" % (name, version)

    def reg_cocoapods(self, r, name, version, deep):
        d = self.net.get("https://trunk.cocoapods.org/api/v1/pods/%s" % urllib.parse.quote(name))
        versions = d.get("versions") or []
        rel = [v for v in versions if not C.is_prerelease(v.get("name", ""))]
        if rel:
            newest = max(rel, key=lambda v: C.version_sort_key(v["name"]))
            r.latest = newest["name"]
            r.last_release = parse_date(newest.get("created_at"))
        spec = self.net.get("https://trunk.cocoapods.org/api/v1/pods/%s/specs/latest" % urllib.parse.quote(name))
        if spec.get("deprecated") or spec.get("deprecated_in_favor_of"):
            alt = spec.get("deprecated_in_favor_of")
            r.deprecated = "CocoaPods marks %s deprecated%s" % (name, ("; use %s instead" % alt) if alt else "")
            if alt:
                r.alternate = {"id": alt}
        src = spec.get("source") or {}
        r.repository = src.get("git") if isinstance(src, dict) else None
        if version and versions and not any(v.get("name") == version for v in versions):
            r.found = False
            r.note = "CocoaPods trunk has no version %s of %s" % (version, name)

    def reg_swifturl(self, r, name, version, deep):
        slug = repo_slug("https://" + name)
        if not slug:
            raise C.FetchError(name, "not hosted on GitHub or GitLab, so there is no registry to ask")
        archived, where, pushed = self.repo_status("https://" + name)
        if archived is None:
            raise C.FetchError(name, where or "repository lookup failed")
        r.source = "GitHub API" if slug[0] == "github" else "GitLab API"
        r.repository = "https://" + name
        # a release needs a push, so the last push date bounds the last release date
        r.last_release, r.last_release_is_bound = pushed, True
        if archived:
            r.inactive = "the source repository %s is archived" % where

    # ------------------------------------------------------------------ per item
    def support_obj(self, status, reason, source=None, eol_date=None, newer_major=None):
        return {"status": status, "out_of_support": status in C.OUT_OF_SUPPORT, "eol_date": eol_date,
                "newer_major_available": newer_major, "reason": reason, "source": source if status != "unknown" else None,
                "checked_at": C.now_iso()}

    def runtime_support(self, rt):
        details = {"endoflife_product": rt.get("endoflife_product")}
        if self.opts.offline:
            return self.support_obj("unknown", "Offline"), details
        version = rt.get("version")
        if not version:
            return self.support_obj("unknown", "The runtime version could not be determined from the evidence."), details
        label = rt["name"]
        result, note = self.eol_status(rt["endoflife_product"], version, label)
        if result is None:
            return self.support_obj("unknown", note), details
        reason = result["reason"]
        if rt.get("version_confidence") == "range" and any("declared" in e for e in rt.get("evidence") or []):
            reason = "Judged on the lowest version the declared range allows (%s). %s" % (version, reason)
        if rt.get("runtime") == "java" and rt.get("endoflife_product_from") != "image":
            reason += " The JDK vendor isn't stated, so Eclipse Temurin's support dates were used."
        details.update(cycle=result["cycle"])
        return self.support_obj(result["status"], reason, result["source"], result["eol_date"],
                                result["newer_major_available"]), details

    def library_support(self, lib):
        details = {}
        if lib.get("private"):
            details["private_reason"] = lib["private"]
            return self.support_obj("unknown", "Private registry"), details
        if self.opts.offline:
            return self.support_obj("unknown", "Offline"), details
        conf = lib.get("version_confidence")
        version = lib.get("version") if conf == "exact" else (lib.get("lowest_version") if conf == "range" else None)
        range_note = ""
        if conf == "range":
            if not version:
                return self.support_obj("unknown", "Only the declared range %s is known and it has no lower bound." % lib.get("version")), details
            range_note = "Judged on the lowest version the declared range allows (%s). " % version
        details["judged_version"] = version
        eol_result, eol_note = None, None
        product = self.eol_product_for(lib)
        if product and version:
            eol_result, eol_note = self.eol_status(product, version, product_label(product), package=lib["name"])
            details["endoflife_product"] = product
            if eol_result:
                details["cycle"] = eol_result["cycle"]
        deep = bool(lib.get("direct"))
        reg = self.check_registry(lib, version, deep) if ECO_KEY.get(lib["ecosystem"]) else None
        policy = self.policy_for(lib)
        if policy:
            details["policy"] = policy

        unmaintained, unmaintained_src = None, None
        if reg is not None and reg.ran:
            details.update({k: v for k, v in (("latest_version", reg.latest), ("repository", C.strip_userinfo(reg.repository) if reg.repository else None),
                                                ("last_release", reg.last_release.isoformat() if reg.last_release else None),
                                                ("alternate_package", reg.alternate)) if v})
            stale = reg.last_release is not None and reg.last_release < self.stale_before
            if deep and stale and not reg.deprecated:
                signal, signal_src = reg.inactive, reg.source
                if not signal and reg.repository:
                    archived, where, _pushed = self.repo_status(reg.repository)
                    if archived:
                        signal = "the source repository %s is archived" % where
                        signal_src = "%s; %s" % ("GitHub API" if where.startswith("github") else "GitLab API", reg.source)
                if signal:
                    when = ("the last release was on %s" % reg.last_release.isoformat()) if not reg.last_release_is_bound else \
                        ("nothing has been published since %s" % reg.last_release.isoformat())
                    unmaintained = "%s%s, and %s, more than %d months ago." % (
                        signal[0].upper(), signal[1:], when, self.opts.unmaintained_months)
                    unmaintained_src = signal_src

        newer = None
        if eol_result and eol_result["newer_major_available"] is not None:
            newer = eol_result["newer_major_available"]
        elif reg is not None and reg.ran and version:
            if lib["ecosystem"] == "Go":
                newer = bool(getattr(reg, "newer_major_path", None)) or (
                    reg.latest is not None and (C.major_of(reg.latest) or 0) > (C.major_of(version) or 0))
            elif reg.latest:
                newer = (C.major_of(reg.latest) or 0) > (C.major_of(version) or 0)

        reg_src = reg.source if reg is not None and reg.ran else None
        if not version:
            # without a version only package-level notices count (Packagist abandoned, pub.dev discontinued,
            # a deprecated Go module, a deprecated pod); a clean lookup says nothing about an unknown version
            if reg is not None and reg.deprecated:
                return self.support_obj("deprecated", reg.deprecated.rstrip(".") + ". This applies to every version.",
                                        reg.source, None, None), details
            if lib["ecosystem"] == "Maven" and not lib.get("declared"):
                why = "The version is managed by a parent POM or BOM that wasn't resolved, so it is unknown."
            else:
                why = "The version could not be determined (%s)." % (lib.get("declared") or "no version in the manifest")
            return self.support_obj("unknown", why), details
        if eol_result and eol_result["status"] == "end-of-life":
            reason = eol_result["reason"]
            if reg is not None and reg.deprecated:
                reason += " Also: %s." % reg.deprecated
            return self.support_obj("end-of-life", range_note + reason, eol_result["source"], eol_result["eol_date"], newer), details
        if reg is not None and reg.deprecated:
            reason = reg.deprecated.rstrip(".") + "."
            if eol_result:
                reason += " (endoflife.date: %s)" % eol_result["reason"]
            return self.support_obj("deprecated", range_note + reason, reg.source,
                                    eol_result["eol_date"] if eol_result else None, newer), details
        if unmaintained:
            return self.support_obj("unmaintained", range_note + unmaintained, unmaintained_src, None, newer), details
        if eol_result and eol_result["status"] == "security-only":
            return self.support_obj("security-only", range_note + eol_result["reason"], eol_result["source"],
                                    eol_result["eol_date"], newer), details
        if eol_result:
            src = eol_result["source"] + ("; " + reg_src if reg_src else "")
            reason = eol_result["reason"]
            if reg is not None and reg.ran and reg.found:
                reason += " No deprecation notice from the %s." % reg_src
            return self.support_obj("supported", range_note + reason, src, eol_result["eol_date"], newer), details
        if reg is not None and reg.ran and reg.found:
            what = "deprecation, yank or archive notice" if deep else "deprecation or yank notice"
            reason = "No end-of-life, %s found (%s)." % (what, reg_src)
            if eol_note and "no release cycle" in eol_note:
                reason += " Note: %s." % eol_note
            if lib["ecosystem"] == "Maven":
                reason = "No end-of-life or archive notice found (%s has no deprecation metadata)." % reg_src
            return self.support_obj("supported", range_note + reason, reg_src, None, newer), details
        if reg is not None and reg.ran and not reg.found:
            return self.support_obj("unknown", range_note + (reg.note or "Not found in the public registry") + ".", None, None, None), details
        why = (reg.note if reg is not None and reg.note else None) or eol_note or "No support source covers the %s ecosystem." % lib["ecosystem"]
        if not version:
            why = "The version could not be determined (%s)." % (lib.get("declared") or "no version in the manifest")
        return self.support_obj("unknown", range_note + why, None, None, newer), details

    def policy_for(self, lib):
        key = ECO_KEY.get(lib["ecosystem"])
        for pol in self.rules.get("policies") or []:
            if any(fnmatch.fnmatchcase(lib["name"].lower(), str(p).lower()) for p in (pol.get("packages") or {}).get(key) or []):
                slug = re.sub(r"[^a-z0-9]+", "-", pol["name"].lower()).strip("-")
                path = self.out / "raw" / "policies" / ("%s.txt" % slug)
                if not path.exists():
                    try:
                        page = self.net.get(pol["url"], kind="text")
                        text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", page)
                        text = html.unescape(re.sub(r"<[^>]+>", " ", text))
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(re.sub(r"[ \t]+", " ", text), encoding="utf-8")
                        with self.lock:
                            self.policies_saved.append({"name": pol["name"], "url": pol["url"], "saved": C.posix(path.relative_to(self.out))})
                    except C.FetchError as e:
                        return {"name": pol["name"], "url": pol["url"], "error": e.message}
                return {"name": pol["name"], "url": pol["url"], "saved": C.posix(path.relative_to(self.out))}
        return None

    # ------------------------------------------------------------------ run
    def run(self):
        if self.opts.offline:
            C.set_offline(True)
        runtimes_out = []
        for rt in self.inv.get("runtimes") or []:
            sup, det = self.runtime_support(rt)
            runtimes_out.append({"id": rt["id"], "support": sup, "details": det})
        libs = self.inv.get("libraries") or []
        # one lookup per (ecosystem, name, judged version, private, direct); results are shared across manifests
        def key(lib):
            return (lib["ecosystem"], lib["name"], lib.get("version"), lib.get("version_confidence"),
                    bool(lib.get("private")), bool(lib.get("direct")))
        unique = {}
        for lib in libs:
            unique.setdefault(key(lib), lib)
        results = {}
        with cf.ThreadPoolExecutor(max_workers=max(1, self.opts.workers)) as pool:
            futs = {pool.submit(self.library_support, lib): k for k, lib in unique.items()}
            for f in cf.as_completed(futs):
                k = futs[f]
                try:
                    results[k] = f.result()
                except Exception as e:  # a bug in one lookup never stops the run
                    results[k] = (self.support_obj("unknown", "Support check failed (%s: %s)." % (type(e).__name__, e)), {})
                    self.errors.append("support check for %s %s failed: %s: %s" % (k[0], k[1], type(e).__name__, e))
        libraries_out = []
        for lib in libs:
            sup, det = results[key(lib)]
            libraries_out.append({"id": lib["id"], "manifest": lib.get("manifest"), "support": dict(sup), "details": det})
        if self.repo_checks["skipped_rate_limit"] or self.github_limited:
            self.gaps.append("GitHub API rate limit reached: the archived-repository check was skipped for some direct dependencies "
                             "(set GITHUB_TOKEN to raise the limit)")
        if not self.opts.offline:
            self.gaps.append("The unmaintained check (archived repository, or a maintainer's inactive notice, plus no release for "
                             "%d months) covers direct dependencies only" % self.opts.unmaintained_months)
        counts = {}
        for item in runtimes_out + libraries_out:
            counts[item["support"]["status"]] = counts.get(item["support"]["status"], 0) + 1
        tools = sorted(self.sources_used)
        return {
            "tool": {"name": "check_support.py", "version": C.TOOL_VERSION},
            "generated_at": C.now_iso(),
            "options": {"offline": bool(self.opts.offline), "unmaintained_months": self.opts.unmaintained_months},
            "sources_used": [{"name": t, "version": "v1" if t == "endoflife.date API" else None} for t in tools],
            "hosts_queried": dict(sorted(self.net.ok_hosts.items())),
            "runtimes": runtimes_out,
            "libraries": libraries_out,
            "policies_saved": self.policies_saved,
            "status_counts": counts,
            "gaps": C.dedupe(self.gaps),
            "errors": C.dedupe(self.net.errors + self.errors),
        }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Look up end-of-life, deprecation and maintenance status.")
    ap.add_argument("--out", required=True, help="output directory holding raw/inventory.json")
    ap.add_argument("--unmaintained-months", type=int, default=24)
    ap.add_argument("--offline", action="store_true", help="no lookups; every status is unknown (Offline)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--no-network-probe", action="store_true", help="skip the up-front reachability check")
    args = ap.parse_args(argv)
    out = Path(args.out)
    inv_path = C.raw_dir(out) / "inventory.json"
    if not inv_path.is_file():
        print("error: %s not found; run detect_inventory.py first" % inv_path, file=sys.stderr)
        return 2
    inventory = C.read_json(inv_path)
    if inventory.get("options", {}).get("offline"):
        args.offline = True
    if not args.offline and not args.no_network_probe:
        # Spec §9 "No network": with neither OSV.dev nor endoflife.date reachable, the whole run must be offline,
        # which detect_inventory.py records. One plain request to each; no package names are sent.
        probes = {h: C.host_reachable("https://%s/" % h) for h in NETWORK_PROBE_HOSTS}
        if not any(ok for ok, _why in probes.values()):
            print("NO NETWORK: %s. Nothing was written. Restart the audit offline: detect_inventory.py ... --offline, "
                  "then the other steps with --offline (spec §9)."
                  % "; ".join("%s unreachable (%s)" % (h, why) for h, (_ok, why) in probes.items()), file=sys.stderr)
            return 3
    checker = SupportChecker(inventory, args, out)
    data = checker.run()
    C.write_json(C.raw_dir(out) / "support.json", data)
    print("wrote %s" % (C.raw_dir(out) / "support.json"))
    print("status counts: %s" % ", ".join("%s %d" % (k, v) for k, v in sorted(data["status_counts"].items(), key=lambda x: STATUS_RANK.get(x[0], 9))))
    print("sources: %s" % (", ".join(s["name"] for s in data["sources_used"]) or "none"))
    names = {}
    for rt in data["runtimes"]:
        if rt["support"]["out_of_support"] or rt["support"]["status"] == "security-only":
            print("  %-13s %s: %s" % (rt["support"]["status"], rt["id"], rt["support"]["reason"]))
    for lib in data["libraries"]:
        s = lib["support"]
        if (s["out_of_support"] or s["status"] == "security-only") and lib["id"] not in names:
            names[lib["id"]] = True
            print("  %-13s %s: %s" % (s["status"], lib["id"], s["reason"][:220]))
    for g in data["gaps"]:
        print("gap: %s" % g)
    for e in data["errors"]:
        print("error: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
