#!/usr/bin/env python3
"""Steps 1-2 of the dependency audit: scope and inventory.

Usage:
    python detect_inventory.py <path> --out <dir> [--offline] [--no-transitive]
                               [--internal PATTERN ...] [--mirror-public]

Walks the project (skipping vendor and build directories), parses manifests and lockfiles for
npm, PyPI, Maven/Gradle, Go, Cargo, RubyGems, Packagist, NuGet, Pub, CocoaPods/SwiftPM, container
base images and vendored JS/CSS, detects runtimes and frameworks, and works out which packages
are private (never looked up publicly, hard rule 5). Writes <out>/raw/inventory.json and prints a
short summary.

Reads files only. No network access, and it never runs package managers or project code.
Registry credentials are dropped as they are read; only a shortened preview (first 4 characters,
an ellipsis and the length) and the file and line are kept.

--internal PATTERN   a package name (glob) that is internal; repeatable. Used after asking the user
                     when one registry serves every package (open question 4).
--mirror-public      packages served by such a mirror may be looked up publicly unless they match
                     --internal. Without it they are all treated as private.
"""
from __future__ import annotations

import argparse
import configparser
import fnmatch
import os
import re
import shutil
import sys
import tomllib
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

PUBLIC_HOSTS = {
    "npm": {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com"},
    "PyPI": {"pypi.org", "files.pythonhosted.org", "pypi.python.org", "download.pytorch.org"},
    "NuGet": {"api.nuget.org", "www.nuget.org", "nuget.org"},
    "Maven": {"repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com", "maven.google.com",
              "dl.google.com", "jitpack.io", "repo.spring.io", "plugins.gradle.org", "oss.sonatype.org",
              "s01.oss.sonatype.org", "packages.confluent.io", "jcenter.bintray.com", "maven.pkg.jetbrains.space"},
    "RubyGems": {"rubygems.org", "gems.ruby-china.com"},
    "Packagist": {"packagist.org", "repo.packagist.org"},
    "Pub": {"pub.dev", "pub.dartlang.org"},
    "crates.io": {"index.crates.io", "github.com", "crates.io"},
}
PUBLIC_GO_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "golang.org", "google.golang.org", "gopkg.in",
                   "go.uber.org", "k8s.io", "sigs.k8s.io", "cloud.google.com", "go.opentelemetry.io", "gorm.io",
                   "honnef.co", "mvdan.cc", "go.etcd.io", "go.mongodb.org", "gotest.tools", "dario.cat",
                   "filippo.io", "lukechampine.com", "modernc.org", "nhooyr.io", "rsc.io", "tailscale.com",
                   "go.temporal.io", "connectrpc.com", "buf.build", "cuelang.org", "go.mozilla.org", "gocloud.dev"}
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock")
SCOPE_RANK = {"runtime": 0, "optional": 1, "build": 2, "dev": 3}
DEV_REQ_FILE = re.compile(r"(^|[-_/.])(dev|test|tests|testing|lint|docs?|ci|typing|types|check)([-_.]|$)", re.I)
UNSUPPORTED_MARKERS = {
    "mix.exs": "Hex (Elixir)", "mix.lock": "Hex (Elixir)", "rebar.config": "Hex (Erlang)",
    "stack.yaml": "Hackage (Haskell)", "cabal.project": "Hackage (Haskell)", "renv.lock": "CRAN (R)",
    "DESCRIPTION": "CRAN (R)", "conanfile.txt": "Conan (C/C++)", "conanfile.py": "Conan (C/C++)",
    "vcpkg.json": "vcpkg (C/C++)", "Manifest.toml": "Julia", "build.sbt": "sbt (Scala)",
    "project.clj": "Leiningen (Clojure)", "deps.edn": "Clojure CLI", "Cartfile": "Carthage",
    "Cartfile.resolved": "Carthage", "bun.lockb": "npm (binary bun.lockb)", "shard.yml": "Crystal shards",
    "elm.json": "Elm", "dub.json": "DUB (D)", "flake.lock": "Nix",
}
LANG_EXT = {".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
            ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
            ".py": "Python", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
            ".groovy": "Groovy", ".cs": "C#", ".vb": "Visual Basic .NET", ".fs": "F#", ".go": "Go",
            ".rs": "Rust", ".rb": "Ruby", ".php": "PHP", ".dart": "Dart", ".swift": "Swift",
            ".m": "Objective-C", ".mm": "Objective-C", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++",
            ".hpp": "C++", ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".hs": "Haskell",
            ".r": "R", ".lua": "Lua", ".pl": "Perl", ".sh": "Shell", ".ps1": "PowerShell", ".vue": "Vue",
            ".svelte": "Svelte", ".yml": "YAML", ".yaml": "YAML", ".tf": "HCL", ".sql": "SQL"}
HTML_EXT = {".html", ".htm", ".cshtml", ".vbhtml", ".aspx", ".ascx", ".master", ".jsp", ".php", ".erb",
            ".ejs", ".hbs", ".handlebars", ".twig", ".j2", ".jinja", ".jinja2", ".liquid", ".mustache"}
VENDORED_NAME = re.compile(
    r"^(?P<lib>jquery-ui|jquery|bootstrap|angular|lodash|underscore|moment|vue|react-dom|react|handlebars|d3"
    r"|backbone|knockout|ember|dojo|prototype|mootools|select2|datatables|tinymce|ckeditor|modernizr|popper"
    r"|axios|socket\.io|highcharts|leaflet|three|dompurify|mustache|chart)"
    r"(?:[.-]v?(?P<ver>\d+\.\d+(?:\.\d+)?))?(?:[.-](?:slim|min|bundle|umd|esm|production|development|full|core|all))*\.(?:js|css)$",
    re.I)
# A banner that names the library itself: the name starts the comment line and the version follows it
# directly ("jQuery v3.6.0", "jQuery UI - v1.12.1", "moment.js" / "version : 2.14.1"). A plugin's banner
# ("jQuery SerializeToJSON v1.4.1", "Jasny Bootstrap v3.1.3") carries the plugin's version, not the library's.
VENDORED_HEADER = re.compile(
    r"(?i)(?<![\w.\-/@])(jquery validation plugin|jquery ui|jquery|bootstrap|angularjs|react(?:-dom)?|vue\.js|vue"
    r"|handlebars|moment(?:\.js)?|lodash|underscore(?:\.js)?|d3|backbone(?:\.js)?|chart\.js|knockout(?:js)?|select2"
    r"|popper(?:\.js)?|axios|socket\.io|leaflet|three\.js|highcharts|tinymce|ckeditor|dompurify|mustache(?:\.js)?"
    r"|datatables|font awesome|sweetalert2|clipboard(?:\.js)?|metismenu)"
    r"(?:[ \t]+(?:javascript[ \t]+library|js|library|free))?[\s\-–—:,|*/!]{0,14}(?:version[\s:]*)?"
    r"v?(\d+\.\d+\.\d+)(?!\w)")
HEADER_LINE_PREFIX = re.compile(r"(?i)@(?:license|preserve|overview|file|name)\b")
VENDOR_NPM_NAME = {"jquery ui": "jquery-ui", "angularjs": "angular", "vue.js": "vue", "moment.js": "moment",
                   "underscore.js": "underscore", "backbone.js": "backbone", "chart.js": "chart.js", "chart": "chart.js",
                   "knockoutjs": "knockout", "popper.js": "popper.js", "popper": "popper.js", "socket.io": "socket.io-client",
                   "three.js": "three", "mustache.js": "mustache", "jqueryui": "jquery-ui", "angular.js": "angular",
                   "jquery validation plugin": "jquery-validation", "datatables": "datatables.net",
                   "font awesome": "font-awesome", "clipboard.js": "clipboard"}
# Folders of a vendored library that hold its demos, docs and tests, not files the application loads.
VENDORED_SKIP_DIRS = {"example", "examples", "demo", "demos", "doc", "docs", "test", "tests", "spec", "sample", "samples"}
# Package metadata a vendored library folder ships with, most reliable first (.bower.json records what
# Bower installed). It identifies that library; it is not a manifest of the project.
VENDORED_METADATA = (".bower.json", "bower.json", "package.json")


def vendored_header(head: str):
    """(library, version) from a file's leading banner comment, or None."""
    for m in VENDORED_HEADER.finditer(head):
        line_start = head.rfind("\n", 0, m.start()) + 1
        if HEADER_LINE_PREFIX.sub("", head[line_start:m.start()]).strip(" \t/*!#<-=") == "":
            return m.group(1).lower(), m.group(2)
    return None


def nuget_norm(version: str) -> str:
    """A NuGet version without trailing zero segments, so 5.0 and 5.0.0 compare equal."""
    core, sep, pre = version.strip().lower().partition("-")
    parts = core.split(".")
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts) + sep + pre
CDN_PATTERNS = [
    re.compile(r"cdn\.jsdelivr\.net/npm/(?P<pkg>@?[\w.\-]+(?:/[\w.\-]+)?)@(?P<ver>\d[\w.\-]*)"),
    re.compile(r"unpkg\.com/(?P<pkg>@?[\w.\-]+(?:/[\w.\-]+)?)@(?P<ver>\d[\w.\-]*)"),
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/(?P<pkg>[\w.\-]+)/(?P<ver>\d[\w.\-]*)/"),
    re.compile(r"ajax\.googleapis\.com/ajax/libs/(?P<pkg>[\w.\-]+)/(?P<ver>\d[\w.\-]*)/"),
    re.compile(r"code\.jquery\.com/ui/(?P<ver>\d[\w.\-]*)/", re.I),
    re.compile(r"code\.jquery\.com/(?P<pkg>jquery)-(?P<ver>\d+\.\d+\.\d+)"),
    re.compile(r"(?:maxcdn|stackpath|netdna)\.bootstrapcdn\.com/(?P<pkg>bootstrap|font-awesome)/(?P<ver>\d[\w.\-]*)/"),
]
# cdnjs / Google library names that differ from the npm package name (keys lower-case)
CDN_NAME_FIX = {"jqueryui": "jquery-ui", "angularjs": "angular", "angular.js": "angular", "twitter-bootstrap": "bootstrap",
                "chart.js": "chart.js", "socket.io": "socket.io-client", "moment.js": "moment", "lodash.js": "lodash",
                "underscore.js": "underscore", "handlebars.js": "handlebars", "backbone.js": "backbone",
                "three.js": "three", "jquery-validate": "jquery-validation", "mustache.js": "mustache",
                "knockout": "knockout", "vue.js": "vue", "react-dom": "react-dom", "ember.js": "ember-source"}
# NuGet packages (keys lower-case) that copy a JS library into the project (Scripts/, Content/) in the
# packages.config era. A vendored file with the same npm name and version inside that project is the
# package's own copy: it is recorded on the NuGet entry (also_installed_as), not as a second library, so
# each advisory is reported once (spec Step 5, "Dedupe").
NUGET_CONTENT_PACKAGES = {"jquery": "jquery", "jquery.ui.combined": "jquery-ui", "jquery.validation": "jquery-validation",
                          "bootstrap": "bootstrap", "modernizr": "modernizr", "knockoutjs": "knockout",
                          "angularjs.core": "angular", "moment.js": "moment"}


def strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def parse_xml_file(path: Path):
    data = path.read_bytes()
    if re.search(rb"<!DOCTYPE", data[:4096], re.I):
        raise ValueError("DOCTYPE declarations are not accepted")
    return strip_ns(ET.fromstring(data))


PRIVATE_TLDS = (".internal", ".local", ".localdomain", ".corp", ".lan", ".intranet", ".intra", ".private",
                ".home.arpa", ".test", ".example", ".invalid", ".localhost")


def private_host(host: str | None) -> bool:
    """True for a host that can only be on a private network (reserved or conventional internal names,
    private IP ranges). Errs towards privacy: such names are never sent to public services."""
    if not host:
        return False
    h = host.lower().rstrip(".")
    if h.endswith(PRIVATE_TLDS) or "." not in h:
        return True
    return bool(re.match(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", h))


def credential_note(value: str, rel: str, line=None) -> str:
    """How a credential found in a config file is recorded: an environment-variable reference by its
    name (no secret in the file), anything else only as the shortened preview (spec Step 1)."""
    where = "%s:%d" % (rel, line) if line else rel
    v = (value or "").strip().strip("\"'")
    m = re.fullmatch(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|%([A-Za-z_][A-Za-z0-9_]*)%", v)
    if m:
        return "reads environment variable %s at %s (no value stored in the file)" % (m.group(1) or m.group(2), where)
    return "%s at %s" % (C.redact_token(v), where)


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    m = re.match(r"^(?:[a-z+]+:)?//(?:[^@/]+@)?([^/:?#]+)", url.strip(), re.I)
    return m.group(1).lower() if m else None


def norm_rel(*parts) -> str:
    p = "/".join(x for x in parts if x not in ("", "."))
    out = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == ".." and out:
            out.pop()
        else:
            out.append(seg)
    return "/".join(out)


def pep508(req: str):
    """Split a PEP 508 requirement into (name, spec, extras_marker_note) or None."""
    req = req.strip()
    if not req or req.startswith(("#", "-")):
        return None
    req = req.split(";", 1)[0].strip()
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$", req)
    if not m:
        return None
    name, spec = m.group(1), m.group(3).strip()
    if spec.startswith("@"):
        return name, None, "direct URL"
    spec = spec.strip("() ")
    return name, (spec or None), None


class Inventory:
    def __init__(self, root: Path, opts):
        self.root = root
        self.opts = opts
        self.libraries: list[dict] = []
        self.lib_index: dict[tuple, dict] = {}
        self.runtimes: dict[str, dict] = {}
        self.errors: list[str] = []
        self.gaps: list[str] = []
        self.leads: list[dict] = []
        self.private_registries: list[dict] = []
        self.mirrors: dict[tuple, dict] = {}
        self.manifests: list[dict] = []
        self.unsupported: dict[str, list[str]] = defaultdict(list)
        self.osv_configs: list[dict] = []
        self.go_modules: list[str] = []
        self.maven_private: list[str] = []
        self.gradle_plugins_seen: set[tuple] = set()  # (artifact, version) already recorded
        self.gradle_builds: list[dict] = []           # builds without gradle.lockfile, for resolve_gradle()
        self.service_images: list[str] = []
        self.plain_requirements: list[str] = []
        self.maven_unknown_versions = 0
        self.nuget_from_assets: list[str] = []
        self.nuget_stale_assets: list[str] = []
        self.nuget_unresolved: list[str] = []
        self.languages: dict[str, int] = defaultdict(int)
        self.files: list[str] = []
        self.all_files: list[tuple] = []
        self.file_set: set[str] = set()
        self.remote_host = C.git_remote_host(root)
        self.support_rules = C.load_rules("support_sources")
        self.image_map = self._image_map()
        self.go_private_patterns = [p.strip() for p in ",".join(
            os.environ.get(k, "") for k in ("GOPRIVATE", "GONOPROXY", "GONOSUMDB")).split(",") if p.strip()]

    # ------------------------------------------------------------------ helpers
    def read(self, rel: str, limit=None) -> str:
        return C.read_text(self.root / rel, limit=limit)

    def exists(self, rel: str) -> bool:
        return rel in self.file_set

    def note_manifest(self, rel, ecosystem, kind):
        self.manifests.append({"path": rel, "ecosystem": ecosystem, "kind": kind})

    def error(self, rel, msg):
        self.errors.append("%s: %s" % (rel, C.redact_text(str(msg))[:300]))

    def scan_leads(self, rel, text):
        for lead in C.find_injection_leads(text, rel):
            if len(self.leads) < 50:
                self.leads.append(lead)

    def add_mirror(self, ecosystem, host, evidence):
        key = (ecosystem, host)
        if key not in self.mirrors:
            self.mirrors[key] = {"ecosystem": ecosystem, "host": host, "evidence": evidence, "packages": 0}

    def add_private_registry(self, ecosystem, host, evidence, scope=None, credential=None):
        """One entry per (ecosystem, host). `credential` is only ever the shortened preview from
        C.redact_token plus its location, never the value itself."""
        for entry in self.private_registries:
            if entry["ecosystem"] == ecosystem and entry["host"] == host:
                if credential and credential not in entry.setdefault("credentials", []):
                    entry["credentials"].append(credential)
                if scope and scope not in entry.setdefault("scopes", []):
                    entry["scopes"].append(scope)
                return
        entry = {"ecosystem": ecosystem, "host": host, "evidence": evidence}
        if scope:
            entry["scopes"] = [scope]
        if credential:
            entry["credentials"] = [credential]
        self.private_registries.append(entry)

    def add_lib(self, *, ecosystem, name, version=None, confidence="unknown", direct=True, scope="runtime",
                manifest=None, lockfile=None, introduced_by=(), license=None, declared=None, workspace=".",
                private=None, mirror=None, lookup_note=None, lowest=None, vendored=False, evidence_line=None):
        if not name:
            return None
        if confidence == "exact" and version:
            version = str(version).strip()
        purl = C.make_purl(ecosystem, name, version)
        key = (manifest or lockfile, purl)
        old = self.lib_index.get(key)
        if old:
            old["direct"] = old["direct"] or direct
            if SCOPE_RANK.get(scope, 9) < SCOPE_RANK.get(old["scope"], 9):
                old["scope"] = scope
            if direct:
                old["introduced_by"] = []
            elif not old["direct"] and introduced_by and (not old["introduced_by"] or len(introduced_by) < len(old["introduced_by"])):
                old["introduced_by"] = list(introduced_by)
            if private and not old.get("private"):
                old["private"] = private
            return old
        entry = {
            "id": purl, "name": name, "ecosystem": ecosystem, "version": version,
            "version_confidence": confidence if version else "unknown",
            "direct": bool(direct), "scope": scope, "license": license,
            "manifest": manifest, "lockfile": lockfile,
            "introduced_by": [] if direct else list(introduced_by),
            "declared": declared, "lowest_version": lowest if confidence == "range" else None,
            "workspace": workspace or ".", "private": private, "mirror": mirror,
            "lookup_note": lookup_note, "vendored": vendored, "line": evidence_line,
        }
        self.lib_index[key] = entry
        self.libraries.append(entry)
        return entry

    @staticmethod
    def runtime_cycle(rid, version):
        """The release-cycle part of a runtime version, used in the runtime id (spec Step 2:
        runtime:nodejs@20, runtime:dotnet@8.0, runtime:dotnetfx@4.6.2)."""
        v = version
        if rid == "java" and re.match(r"^1\.\d", v):
            v = v[2:]  # 1.8 -> 8
        parts = v.split(".")
        if rid in ("nodejs", "java", "debian", "amazon-linux", "gradle", "android"):
            n = 2 if (rid == "nodejs" and parts[0] == "0") else 1
        elif rid == "dotnetfx":
            n = 3
        else:
            n = 2
        cycle = ".".join(parts[:n])
        if rid == "dotnet" and "." not in cycle:
            cycle += ".0"
        return cycle

    def add_runtime(self, rid, version, confidence, evidence, product=None):
        rule = next((r for r in self.support_rules.get("runtimes", []) if r["id"] == rid), None)
        if rule is None:
            return
        version = (str(version).strip() if version is not None else None) or None
        concrete = None
        if version:
            version = re.sub(r"^[vV]", "", version)
            base = (C.lowest_in_range(version) or version) if confidence == "range" else version
            m = re.match(r"\d+(?:\.\d+){0,2}", base or "")
            concrete = m.group(0) if m else None
            if concrete and confidence == "range" and version != concrete:
                evidence = "%s, declared %s" % (evidence, version) if "declared" not in evidence else evidence
        if not concrete:
            confidence = "unknown"
        cycle = self.runtime_cycle(rid, concrete) if concrete else None
        rt_id = "runtime:%s@%s" % (rid, cycle) if cycle else "runtime:%s" % rid
        entry = self.runtimes.get(rt_id)
        if entry is None:
            entry = {"id": rt_id, "name": rule["runtime"], "runtime": rid, "version": concrete, "cycle": cycle,
                     "version_confidence": confidence, "evidence": [],
                     "endoflife_product": product or rule.get("endoflife_product"),
                     # "image" when a container image named the vendor (Java), else the rules default
                     "endoflife_product_from": "image" if product else "rules"}
            self.runtimes[rt_id] = entry
        elif concrete:
            # keep the most precise version: an exact one beats a range, a longer one beats a shorter one
            better = (confidence == "exact" and entry["version_confidence"] != "exact") or (
                confidence == entry["version_confidence"] and len(concrete.split(".")) > len((entry["version"] or "").split(".")))
            if better:
                entry["version"], entry["version_confidence"] = concrete, confidence
        if product and (product != entry["endoflife_product"] or entry["endoflife_product_from"] != "image"):
            entry["endoflife_product"] = product
            entry["endoflife_product_from"] = "image"
        if evidence not in entry["evidence"]:
            entry["evidence"].append(evidence)

    def _image_map(self):
        out = {}
        for r in self.support_rules.get("runtimes", []):
            for img in r.get("images", []) or []:
                if isinstance(img, dict):
                    out[img["image"].lower()] = (r["id"], img.get("endoflife_product"))
                else:
                    out[str(img).lower()] = (r["id"], None)
        return out

    # ------------------------------------------------------------------ walk
    def walk(self):
        extra = C.gitignore_dirs(self.root)
        files, excluded = C.walk_project(self.root, extra_excludes=extra)
        self.all_files = files
        self.files = [f for f, vendor_only in files if not vendor_only]
        self.file_set = set(self.files)
        self.excluded = excluded
        for rel, _ in files:
            name = rel.rsplit("/", 1)[-1]
            if name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile."):
                self.languages["Dockerfile"] += 1
                continue
            ext = os.path.splitext(name)[1]
            lang = LANG_EXT.get(ext) or LANG_EXT.get(ext.lower())
            if lang:
                self.languages[lang] += 1

    # ------------------------------------------------------------------ main dispatch
    def run(self):
        self.walk()
        by_dir = defaultdict(set)
        for rel in self.files:
            d, _, name = rel.rpartition("/")
            by_dir[d].add(name)
        dirs = sorted(by_dir, key=lambda d: (d.count("/") + (1 if d else 0), d))
        self.npm_covered: dict[str, str] = {}
        self.cargo_covered: set[str] = set()
        handlers = [self.do_npm, self.do_python, self.do_maven, self.do_gradle, self.do_go, self.do_cargo,
                    self.do_ruby, self.do_composer, self.do_nuget, self.do_pub, self.do_cocoapods, self.do_swift,
                    self.do_docker, self.do_runtime_files, self.do_ci, self.do_misc]
        for d in dirs:
            names = by_dir[d]
            for handler in handlers:
                try:
                    handler(d, names)
                except Exception as e:  # one bad file never stops the inventory
                    self.error(d or ".", "%s failed: %s: %s" % (handler.__name__, type(e).__name__, e))
        try:
            self.do_vendored()
        except Exception as e:
            self.error(".", "vendored JS/CSS scan failed: %s" % e)
        self.apply_privacy()
        try:
            self.resolve_gradle()
        except Exception as e:
            self.error(".", "Gradle dependency resolution failed: %s: %s" % (type(e).__name__, e))
        self.frameworks = self.detect_frameworks()

    def rel(self, d, name):
        return "%s/%s" % (d, name) if d else name

    # ------------------------------------------------------------------ npm
    def npmrc(self, d):
        """Registries from .npmrc / .yarnrc.yml in d and its ancestors: (default_host, {scope: host})."""
        default, scopes = None, {}
        parts = d.split("/") if d else []
        for i in range(len(parts), -1, -1):
            base = "/".join(parts[:i])
            for fname in (".npmrc", ".yarnrc.yml", ".yarnrc"):
                rel = self.rel(base, fname)
                if not self.exists(rel):
                    continue
                text = self.read(rel)
                self.scan_leads(rel, text)
                for n, line in enumerate(text.splitlines(), 1):
                    s = line.strip()
                    if not s or s.startswith(("#", ";")):
                        continue
                    m = re.match(r"^(@[\w.\-]+):registry\s*=\s*(\S+)", s)
                    if m:
                        scopes.setdefault(m.group(1), host_of(m.group(2)))
                        continue
                    m = re.match(r"^registry\s*=\s*(\S+)", s) or re.match(r"^npmRegistryServer:\s*[\"']?(\S+?)[\"']?$", s)
                    if m and default is None:
                        default = host_of(m.group(1))
                        continue
                    m = re.match(r"^(\S*?):?(_authToken|_auth|_password|npmAuthToken|npmAuthIdent)\s*[=:]\s*[\"']?(\S+?)[\"']?$", s)
                    if m:
                        host = host_of("https:" + m.group(1)) if m.group(1).startswith("//") else None
                        self.add_private_registry("npm", host or "(unspecified)", "%s:%d" % (rel, n),
                                                  credential=credential_note(m.group(3), rel, n))
                for m in re.finditer(r"(?m)^\s{2}([\w.\-]+):\s*\n\s{4}npmRegistryServer:\s*[\"']?(\S+?)[\"']?\s*$", text):
                    scopes.setdefault("@" + m.group(1), host_of(m.group(2)))
        return default, scopes

    def npm_classify(self, name, resolved, default_host, scopes, spec=None):
        """Return (private_reason, mirror_host)."""
        if spec and re.match(r"^(file:|link:|portal:|workspace:|git\+|git:|github:|gitlab:|bitbucket:|https?://)", str(spec)):
            return "local, git or URL dependency (%s)" % str(spec).split(":", 1)[0], None
        if resolved and re.match(r"^(file:|git\+|git:|github:|gitlab:|bitbucket:|\.{1,2}/)", str(resolved)):
            return "local or git dependency", None
        if name.startswith("@"):
            scope = name.split("/", 1)[0]
            host = scopes.get(scope)
            if host and host not in PUBLIC_HOSTS["npm"]:
                return "scoped registry %s (%s)" % (host, scope), None
        rh = host_of(resolved) if resolved and re.match(r"^https?://", str(resolved)) else None
        if rh and rh not in PUBLIC_HOSTS["npm"]:
            return None, rh
        if not rh and default_host and default_host not in PUBLIC_HOSTS["npm"]:
            return None, default_host
        return None, None

    def do_npm(self, d, names):
        has_pkg = "package.json" in names
        locks = [n for n in NPM_LOCKS if n in names]
        if not has_pkg and not locks:
            return
        ws = d or "."
        if ws in self.npm_covered and not locks:
            return  # a workspace member; the root lockfile covered it
        manifest = self.rel(d, "package.json") if has_pkg else None
        pkg = {}
        if has_pkg:
            text = self.read(manifest)
            self.scan_leads(manifest, text)
            try:
                pkg = C.load_jsonc(text) if text.strip() else {}
            except ValueError as e:
                self.error(manifest, "invalid JSON (%s)" % e)
                pkg = {}
            self.note_manifest(manifest, "npm", "manifest")
            eng = (pkg.get("engines") or {}).get("node") if isinstance(pkg.get("engines"), dict) else None
            if eng:
                self.add_runtime("nodejs", eng, "range", "%s (engines)" % manifest)
            volta = (pkg.get("volta") or {}).get("node") if isinstance(pkg.get("volta"), dict) else None
            if volta:
                self.add_runtime("nodejs", volta, "exact", "%s (volta)" % manifest)
        default_host, scopes = self.npmrc(d)
        members = self.npm_members(d, pkg)
        for m in members:
            self.npm_covered[m] = d or "."
        if len(locks) > 1:
            self.errors.append("%s: several lockfiles (%s); used %s" % (ws, ", ".join(locks), locks[0]))
        lock = locks[0] if locks else None
        importers = {".": pkg}
        for m in members:
            mrel = self.rel(m, "package.json") if m != "." else "package.json"
            try:
                importers[m] = C.load_jsonc(self.read(mrel))
                self.note_manifest(mrel, "npm", "manifest")
                self.scan_leads(mrel, self.read(mrel))
            except (OSError, ValueError) as e:
                self.error(mrel, "invalid JSON (%s)" % e)
        ctx = {"d": d, "lock": self.rel(d, lock) if lock else None, "default_host": default_host, "scopes": scopes,
               "importers": importers,
               # workspace members referenced by other members are local code, not libraries
               "member_names": {ipkg.get("name") for k, ipkg in importers.items() if k != "." and isinstance(ipkg, dict)}}
        if lock is None:
            for imp_dir, ipkg in importers.items():
                self.npm_manifest_only(ctx, imp_dir, ipkg)
            if has_pkg and any((pkg.get(k) or {}) for k in ("dependencies", "devDependencies", "optionalDependencies")):
                self.gaps.append("%s: no lockfile; declared version ranges only" % manifest)
            return
        lock_rel = ctx["lock"]
        self.note_manifest(lock_rel, "npm", "lockfile")
        try:
            if lock in ("package-lock.json", "npm-shrinkwrap.json"):
                self.parse_package_lock(ctx, C.load_jsonc(self.read(lock_rel)))
            elif lock == "pnpm-lock.yaml":
                self.parse_pnpm(ctx, C.load_yaml(self.read(lock_rel)))
            elif lock == "yarn.lock":
                text = self.read(lock_rel)
                if "__metadata:" in text[:2000]:
                    self.parse_yarn_berry(ctx, C.load_yaml(text))
                else:
                    self.parse_yarn_v1(ctx, text)
            elif lock == "bun.lock":
                self.parse_bun(ctx, C.load_jsonc(self.read(lock_rel)))
        except Exception as e:
            self.error(lock_rel, "could not parse (%s: %s); using declared ranges" % (type(e).__name__, e))
            for imp_dir, ipkg in importers.items():
                self.npm_manifest_only(ctx, imp_dir, ipkg)

    def npm_members(self, d, pkg):
        patterns = []
        w = pkg.get("workspaces")
        if isinstance(w, list):
            patterns += w
        elif isinstance(w, dict):
            patterns += w.get("packages") or []
        pnpm_ws = self.rel(d, "pnpm-workspace.yaml")
        if self.exists(pnpm_ws):
            try:
                patterns += (C.load_yaml(self.read(pnpm_ws)) or {}).get("packages") or []
            except C.YamlError as e:
                self.error(pnpm_ws, e)
        members = []
        if not patterns:
            return members
        prefix = (d + "/") if d else ""
        for f in self.files:
            if not f.startswith(prefix) or not f.endswith("/package.json"):
                continue
            mdir = f[: -len("/package.json")]
            sub = mdir[len(prefix):]
            if any(fnmatch.fnmatch(sub, str(p).rstrip("/")) for p in patterns if not str(p).startswith("!")):
                members.append(mdir)
        return members

    def npm_declared(self, ipkg):
        out = []
        for key, scope in (("dependencies", "runtime"), ("optionalDependencies", "optional"), ("devDependencies", "dev")):
            deps = ipkg.get(key) or {}
            if isinstance(deps, dict):
                for name, spec in deps.items():
                    out.append((name, str(spec), scope))
        return out

    def npm_manifest_only(self, ctx, imp_dir, ipkg):
        manifest = self.rel(imp_dir if imp_dir != "." else ctx["d"], "package.json") if imp_dir == "." else self.rel(imp_dir, "package.json")
        for name, spec, scope in self.npm_declared(ipkg):
            if name in ctx.get("member_names", ()):
                continue
            priv, mirror = self.npm_classify(name, None, ctx["default_host"], ctx["scopes"], spec)
            version, conf, low = C.classify_declared(spec, "npm")
            if priv:
                version, conf, low = (spec if spec else None), "unknown", None
            self.add_lib(ecosystem="npm", name=name, version=version, confidence=conf, direct=True, scope=scope,
                         manifest=manifest, declared=spec, workspace=imp_dir if imp_dir != "." else (ctx["d"] or "."),
                         private=priv, mirror=mirror, lowest=low)

    def _importer_manifest(self, ctx, imp_dir):
        if imp_dir in (".", ""):
            return self.rel(ctx["d"], "package.json") if "package.json" in self.file_names(ctx["d"]) else None
        return self.rel(imp_dir, "package.json") if not imp_dir.startswith(ctx["d"] + "/") and ctx["d"] else (
            imp_dir + "/package.json")

    def file_names(self, d):
        prefix = (d + "/") if d else ""
        return {f[len(prefix):] for f in self.files if f.startswith(prefix) and "/" not in f[len(prefix):]}

    def npm_bfs(self, ctx, imp_dir, roots, nodes, edges_of, label_of, meta_of):
        """Generic BFS from an importer's declared roots over a lockfile graph.
        roots: list of (node_key or None, name, spec, scope). Runtime roots go first so they win."""
        manifest = self.rel(imp_dir, "package.json") if imp_dir not in (".", "") else self.rel(ctx["d"], "package.json")
        if manifest not in self.file_set:
            manifest = None
        ws = imp_dir if imp_dir not in (".", "") else (ctx["d"] or ".")
        seen = set()
        order = sorted(roots, key=lambda r: SCOPE_RANK.get(r[3], 9))
        for key, name, spec, scope in order:
            if name in ctx.get("member_names", ()):
                continue
            if key is None:
                priv, mirror = self.npm_classify(name, None, ctx["default_host"], ctx["scopes"], spec)
                version, conf, low = C.classify_declared(spec, "npm")
                if not priv:
                    self.errors.append("%s: %s is declared but missing from the lockfile" % (ctx["lock"], name))
                self.add_lib(ecosystem="npm", name=name, version=None if priv else version, confidence="unknown" if priv else conf,
                             direct=True, scope=scope, manifest=manifest, lockfile=ctx["lock"], declared=spec,
                             workspace=ws, private=priv, mirror=mirror, lowest=low)
                continue
            queue = deque([(key, [], True)])
            while queue:
                k, chain, is_direct = queue.popleft()
                if k in seen:
                    if is_direct:
                        lib = self.lib_index.get((manifest or ctx["lock"], C.make_purl("npm", *label_of(k))))
                        if lib:
                            lib["direct"] = True
                            lib["introduced_by"] = []
                            lib["declared"] = lib.get("declared") or spec
                    continue
                seen.add(k)
                nm, ver = label_of(k)
                meta = meta_of(k)
                priv, mirror = self.npm_classify(nm, meta.get("resolved"), ctx["default_host"], ctx["scopes"],
                                                 spec if is_direct else None)
                self.add_lib(ecosystem="npm", name=nm, version=ver, confidence="exact" if ver else "unknown",
                             direct=is_direct, scope=scope, manifest=manifest, lockfile=ctx["lock"],
                             introduced_by=chain, license=meta.get("license"), declared=spec if is_direct else None,
                             workspace=ws, private=priv, mirror=mirror)
                for child in edges_of(k):
                    if child is not None and child not in seen:
                        queue.append((child, chain + ["%s@%s" % (nm, ver)], False))

    def parse_package_lock(self, ctx, lock):
        pkgs = lock.get("packages")
        if pkgs is None:
            pkgs = {}

            def flatten(deps, base):
                for name, info in (deps or {}).items():
                    path = (base + "/node_modules/" + name) if base else "node_modules/" + name
                    pkgs[path] = {"version": info.get("version"), "resolved": info.get("resolved"),
                                  "dependencies": info.get("requires") or {}, "dev": info.get("dev"),
                                  "optional": info.get("optional")}
                    flatten(info.get("dependencies"), path)

            flatten(lock.get("dependencies"), "")
            pkgs[""] = ctx["importers"].get(".", {})
        def resolve(from_path, name):
            base = from_path
            while True:
                cand = (base + "/node_modules/" + name) if base else "node_modules/" + name
                if cand in pkgs:
                    info = pkgs[cand]
                    if info.get("link"):
                        return None
                    return cand
                if not base:
                    return None
                idx = base.rfind("/node_modules/")
                if idx >= 0:
                    base = base[:idx]
                elif base.startswith("node_modules/"):
                    base = ""
                else:
                    base = ""

        def label_of(k):
            info = pkgs.get(k, {})
            return info.get("name") or k.rsplit("node_modules/", 1)[-1], info.get("version")

        def meta_of(k):
            info = pkgs.get(k, {})
            lic = info.get("license")
            return {"resolved": info.get("resolved"), "license": lic if isinstance(lic, str) else None}

        def edges_of(k):
            info = pkgs.get(k, {})
            out = []
            for key in ("dependencies", "optionalDependencies", "peerDependencies"):
                for dep in (info.get(key) or {}):
                    if key == "peerDependencies" and resolve(k, dep) is None:
                        continue
                    out.append(resolve(k, dep))
            return out

        importer_dirs = [p for p in pkgs if p and "node_modules/" not in p and not p.startswith("node_modules")]
        for imp in [""] + importer_dirs:
            info = pkgs.get(imp, {}) if imp else (pkgs.get("") or ctx["importers"].get(".", {}))
            declared = self.npm_declared(info) or self.npm_declared(ctx["importers"].get(imp or ".", {}))
            roots = []
            for name, spec, scope in declared:
                k = resolve(imp, name)
                roots.append((k, name, spec, scope))
            imp_dir = norm_rel(ctx["d"], imp) if imp else (ctx["d"] or ".")
            self.npm_bfs(ctx, imp_dir or ".", roots, pkgs, edges_of, label_of, meta_of)

    def parse_pnpm(self, ctx, lock):
        lock = lock or {}
        ver = str(lock.get("lockfileVersion", "5"))
        major = int(re.match(r"\d+", ver).group(0)) if re.match(r"\d+", ver) else 5
        packages = lock.get("packages") or {}
        snapshots = lock.get("snapshots") or {}
        importers = lock.get("importers")
        if importers is None:
            importers = {".": {k: lock.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies", "specifiers")}}

        def key_for(name, ref):
            ref = str(ref)
            if ref.startswith("link:") or ref.startswith("file:"):
                return None
            if major >= 9:
                if not re.match(r"^\d", ref) and "@" in ref.lstrip("@"):
                    return ref  # alias like "real-name@1.2.3"
                return "%s@%s" % (name, ref)
            if major >= 6:
                if ref.startswith("/"):
                    return ref
                return "/%s@%s" % (name, ref)
            if ref.startswith("/"):
                return ref
            return "/%s/%s" % (name, ref)

        def label_of(k):
            s = k.lstrip("/")
            s = re.sub(r"\(.*$", "", s)
            if major >= 6:
                at = s.rfind("@")
                if at > 0:
                    return s[:at], s[at + 1:]
                return s, None
            parts = s.split("/")
            if s.startswith("@") and len(parts) >= 3:
                return "/".join(parts[:2]), parts[2].split("_", 1)[0]
            return parts[0], (parts[1].split("_", 1)[0] if len(parts) > 1 else None)

        def info_of(k):
            if major >= 9:
                return snapshots.get(k) or packages.get(re.sub(r"\(.*$", "", k)) or {}
            return packages.get(k) or {}

        def meta_of(k):
            base = packages.get(re.sub(r"\(.*$", "", k) if major >= 9 else k) or {}
            res = base.get("resolution") or {}
            return {"resolved": res.get("tarball") if isinstance(res, dict) else None, "license": None}

        def edges_of(k):
            info = info_of(k)
            out = []
            for key in ("dependencies", "optionalDependencies"):
                for dep, ref in (info.get(key) or {}).items():
                    out.append(key_for(dep, ref))
            return out

        for imp, data in importers.items():
            data = data or {}
            roots = []
            for key, scope in (("dependencies", "runtime"), ("optionalDependencies", "optional"), ("devDependencies", "dev")):
                for name, ref in (data.get(key) or {}).items():
                    if isinstance(ref, dict):
                        spec, version = ref.get("specifier"), ref.get("version")
                    else:
                        spec, version = (data.get("specifiers") or {}).get(name), ref
                    if version is not None and str(version).startswith("link:"):
                        continue  # a workspace member; its own importer covers it
                    if version is not None and str(version).startswith("file:"):
                        self.add_lib(ecosystem="npm", name=name, direct=True, scope=scope, manifest=None,
                                     lockfile=ctx["lock"], declared=spec, workspace=norm_rel(ctx["d"], imp) or ".",
                                     private="local file dependency")
                        continue
                    k = key_for(name, version) if version is not None else None
                    roots.append((k, name, spec, scope))
            imp_dir = norm_rel(ctx["d"], imp) if imp not in (".", "") else (ctx["d"] or ".")
            self.npm_bfs(ctx, imp_dir or ".", roots, packages, edges_of, label_of, meta_of)

    def parse_yarn_v1(self, ctx, text):
        entries, spec_to_node = {}, {}
        cur, section = None, None
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            s = line.strip()
            if indent == 0 and s.endswith(":"):
                specs = [x.strip().strip('"') for x in s[:-1].split(",")]
                cur = {"specs": specs, "deps": {}, "version": None, "resolved": None}
                section = None
                first = specs[0]
                at = first.rfind("@", 1)
                cur["name"] = first[:at] if at > 0 else first
                node = "%s#%d" % (cur["name"], len(entries))
                entries[node] = cur
                for sp in specs:
                    spec_to_node[sp] = node
            elif cur is not None and indent == 2:
                if s.endswith(":"):
                    section = s[:-1]
                    continue
                section = None
                m = re.match(r'^(\w+)\s+"?([^"]*)"?$', s)
                if m and m.group(1) in ("version", "resolved"):
                    cur[m.group(1)] = m.group(2)
            elif cur is not None and indent >= 4 and section in ("dependencies", "optionalDependencies"):
                m = re.match(r'^"?([^"\s]+)"?\s+"?([^"]*)"?$', s)
                if m:
                    cur["deps"][m.group(1)] = m.group(2)

        def label_of(k):
            e = entries[k]
            return e["name"], e["version"]

        def meta_of(k):
            return {"resolved": entries[k]["resolved"], "license": None}

        def edges_of(k):
            return [spec_to_node.get("%s@%s" % (n, r)) for n, r in entries[k]["deps"].items()]

        for imp_dir, ipkg in ctx["importers"].items():
            roots = []
            for name, spec, scope in self.npm_declared(ipkg):
                roots.append((spec_to_node.get("%s@%s" % (name, spec)), name, spec, scope))
            idir = imp_dir if imp_dir != "." else (ctx["d"] or ".")
            self.npm_bfs(ctx, idir, roots, entries, edges_of, label_of, meta_of)

    def parse_yarn_berry(self, ctx, lock):
        entries, desc_to_key = {}, {}
        for key, info in (lock or {}).items():
            if key == "__metadata" or not isinstance(info, dict):
                continue
            entries[key] = info
            for desc in str(key).split(","):
                desc_to_key[desc.strip()] = key

        def name_of_desc(desc):
            at = desc.find("@", 1)
            return desc[:at] if at > 0 else desc

        def label_of(k):
            info = entries[k]
            res = str(info.get("resolution") or k.split(",")[0])
            return name_of_desc(res), str(info.get("version")) if info.get("version") is not None else None

        def meta_of(k):
            return {"resolved": None, "license": None}

        def lookup(name, rng):
            rng = str(rng)
            for cand in ("%s@%s" % (name, rng), "%s@npm:%s" % (name, rng)):
                if cand in desc_to_key:
                    return desc_to_key[cand]
            return None

        def edges_of(k):
            info = entries[k]
            out = []
            for key in ("dependencies", "optionalDependencies"):
                for dep, rng in (info.get(key) or {}).items():
                    out.append(lookup(dep, rng))
            return out

        for imp_dir, ipkg in ctx["importers"].items():
            roots = []
            for name, spec, scope in self.npm_declared(ipkg):
                if str(spec).startswith("workspace:"):
                    continue
                k = lookup(name, spec)
                if k and "@workspace:" in str(entries[k].get("resolution", "")):
                    continue
                roots.append((k, name, spec, scope))
            idir = imp_dir if imp_dir != "." else (ctx["d"] or ".")
            self.npm_bfs(ctx, idir, roots, entries, edges_of, label_of, meta_of)

    def parse_bun(self, ctx, lock):
        packages = lock.get("packages") or {}
        workspaces = lock.get("workspaces") or {"": ctx["importers"].get(".", {})}

        def label_of(k):
            ident = str(packages[k][0])
            at = ident.rfind("@")
            return (ident[:at], ident[at + 1:]) if at > 0 else (ident, None)

        def meta_of(k):
            v = packages[k]
            return {"resolved": v[1] if len(v) > 1 and isinstance(v[1], str) and v[1].startswith("http") else None,
                    "license": None}

        def resolve(from_key, dep):
            base = from_key
            while base:
                cand = base + "/" + dep
                if cand in packages:
                    return cand
                base = base.rsplit("/", 1)[0] if "/" in base else ""
            return dep if dep in packages else None

        def edges_of(k):
            v = packages[k]
            meta = v[2] if len(v) > 2 and isinstance(v[2], dict) else {}
            out = []
            for key in ("dependencies", "optionalDependencies"):
                for dep in (meta.get(key) or {}):
                    out.append(resolve(k, dep))
            return out

        for imp, data in workspaces.items():
            roots = []
            for name, spec, scope in self.npm_declared(data or {}):
                k = name if name in packages else None
                if k and "@workspace:" in str(packages[k][0]):
                    continue
                roots.append((k, name, spec, scope))
            imp_dir = norm_rel(ctx["d"], imp) if imp else (ctx["d"] or ".")
            self.npm_bfs(ctx, imp_dir or ".", roots, packages, edges_of, label_of, meta_of)

    # ------------------------------------------------------------------ Python
    def pypi_index_check(self, url, rel, line, kind):
        h = host_of(url)
        where = "%s:%d" % (rel, line) if line else rel
        if url and "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            userinfo = url.split("//", 1)[-1].split("@", 1)[0]
            secret = userinfo.split(":", 1)[1] if ":" in userinfo else userinfo
            self.add_private_registry("PyPI", h or "(unspecified)", where,
                                      credential="credentials in the index URL: %s" % credential_note(secret, rel, line))
        if h and h not in PUBLIC_HOSTS["PyPI"]:
            # an index or extra index that isn't PyPI can serve internal names alongside public ones, so it is
            # handled like a mirror (open question 4)
            self.add_mirror("PyPI", h, "%s (%s)" % (where, kind))
            return h
        return None

    def do_python(self, d, names):
        for conf in ("pip.conf", "pip.ini"):
            if conf in names:
                self.parse_pip_conf(self.rel(d, conf))
        req_files = [n for n in names if re.match(r"^requirements.*\.(txt|in)$", n, re.I)]
        in_req_dir = d.split("/")[-1] == "requirements"
        if in_req_dir:
            req_files += [n for n in names if n.endswith((".txt", ".in")) and n not in req_files]
        # the base file first, so a file that includes it (-r requirements.txt) doesn't parse it again
        base_names = ("requirements.txt", "requirements.in", "base.txt", "common.txt", "prod.txt", "production.txt")
        req_files.sort(key=lambda n: (0 if n.lower() in base_names else 1, n))
        has_pyproject = "pyproject.toml" in names
        lockfile = next((n for n in ("poetry.lock", "uv.lock", "Pipfile.lock") if n in names), None)
        ws = (d.rsplit("/", 1)[0] or ".") if in_req_dir and "/" in d else ("." if in_req_dir else (d or "."))
        if has_pyproject or "Pipfile" in names or lockfile or "setup.py" in names or "setup.cfg" in names:
            self.python_project(d, names, lockfile)
        seen = set()
        for f in req_files:
            # pip-compile output next to its .in file: parse the compiled .txt only
            if f.endswith(".in") and f[:-3] + ".txt" in names:
                continue
            self.parse_requirements(self.rel(d, f), ws, seen)

    def parse_pip_conf(self, rel):
        cp = configparser.ConfigParser(interpolation=None)
        try:
            cp.read_string(self.read(rel))
        except configparser.Error as e:
            self.error(rel, "could not parse (%s)" % e)
            return
        for section in cp.sections():
            for key in ("index-url", "extra-index-url"):
                if cp.has_option(section, key):
                    for url in cp.get(section, key).split():
                        self.pypi_index_check(url, rel, None, key)

    def parse_requirements(self, rel, ws, seen, scope_hint=None):
        if rel in seen or not self.exists(rel):
            return
        seen.add(rel)
        text = self.read(rel)
        self.note_manifest(rel, "PyPI", "manifest")
        self.scan_leads(rel, text)
        stem = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        scope = scope_hint or ("dev" if DEV_REQ_FILE.search(stem) or "/requirements/dev" in "/" + rel else "runtime")
        base = rel.rsplit("/", 1)[0] if "/" in rel else ""
        # logical lines (backslash continuations joined), each with its first physical line number
        logical, buf, start = [], "", None
        for n, raw in enumerate(text.splitlines(), 1):
            start = n if start is None else start
            if raw.rstrip().endswith("\\"):
                buf += raw.rstrip()[:-1] + " "
                continue
            logical.append((start, buf + raw))
            buf, start = "", None
        if buf:
            logical.append((start, buf))
        compiled = any(re.match(r"^\s+#\s+via\b", t) for _, t in logical)
        if not compiled:
            self.plain_requirements.append(rel)
        mirror = None
        pending = []
        for i, (n, raw) in enumerate(logical):
            line = "" if raw.strip().startswith("#") else re.split(r"\s+#", raw, maxsplit=1)[0].strip()
            if not line:
                continue
            via = self.pip_compile_via(logical, i) if compiled else None
            m = re.match(r"^(-r|--requirement|-c|--constraint)\s*=?\s*(\S+)", line)
            if m:
                if m.group(1) in ("-r", "--requirement"):
                    # an included file takes its scope from its own name (requirements.txt stays runtime
                    # when requirements-dev.txt includes it)
                    self.parse_requirements(norm_rel(base, m.group(2)), ws, seen)
                continue
            m = re.match(r"^(-i|--index-url|--extra-index-url)\s*=?\s*(\S+)", line)
            if m:
                h = self.pypi_index_check(m.group(2), rel, n, m.group(1).lstrip("-"))
                mirror = mirror or h
                continue
            if line.startswith(("-e", "--editable", "git+", "hg+", "svn+", "bzr+", "http://", "https://", "file:", "./", "../", "/")):
                name = None
                mm = re.search(r"#egg=([A-Za-z0-9._\-]+)", line)
                if mm:
                    name = mm.group(1)
                if name:
                    self.add_lib(ecosystem="PyPI", name=name, direct=True, scope=scope, manifest=rel, workspace=ws,
                                 private="local, editable or VCS requirement", declared=C.strip_userinfo(line)[:200])
                continue
            if line.startswith("-"):
                continue
            line = re.sub(r"\s--hash[=\s]\S+", "", line)
            parsed = pep508(line)
            if not parsed:
                continue
            name, spec, note = parsed
            if note:
                self.add_lib(ecosystem="PyPI", name=name, direct=True, scope=scope, manifest=rel, workspace=ws,
                             private="direct URL requirement")
                continue
            pending.append((name, spec, n, via))
        for name, spec, n, via in pending:
            version, conf, low = C.classify_declared(spec, "PyPI")
            direct = not (compiled and via)
            self.add_lib(ecosystem="PyPI", name=name, version=version, confidence=conf, direct=direct, scope=scope,
                         manifest=rel, introduced_by=[via] if via and not direct else [], declared=spec,
                         workspace=ws, mirror=mirror, lowest=low, evidence_line=n)
        if any(c == "range" for c in (C.classify_declared(s, "PyPI")[1] for _, s, _, _ in pending)):
            unpinned = sum(1 for _, s, _, _ in pending if C.classify_declared(s, "PyPI")[1] != "exact")
            self.gaps.append("%s: %d unpinned requirement(s); declared ranges only" % (rel, unpinned))

    @staticmethod
    def pip_compile_via(logical, i):
        """The parent named in pip-compile '# via' comments under logical line i, or None when the
        requirement is direct ('# via -r requirements.in') or not annotated."""
        vias = []
        for _, t in logical[i + 1:i + 40]:
            m = re.match(r"^\s+#\s*(.*)$", t)
            if not m:
                break
            body = m.group(1).strip()
            if body.startswith("via"):
                body = body[3:].strip()
            if body:
                vias.append(body)
        if not vias or any(v.startswith("-r") for v in vias):
            return None
        parents = [v for v in vias if not v.startswith("-c")]
        return parents[0] if parents else None

    def python_project(self, d, names, lockfile):
        ws = d or "."
        manifest = None
        declared = []  # (name, spec, scope, private_reason)
        sources = {}
        if "pyproject.toml" in names:
            manifest = self.rel(d, "pyproject.toml")
            text = self.read(manifest)
            self.scan_leads(manifest, text)
            self.note_manifest(manifest, "PyPI", "manifest")
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError as e:
                self.error(manifest, "invalid TOML (%s)" % e)
                data = {}
            proj = data.get("project") or {}
            if proj.get("requires-python"):
                self.add_runtime("python", proj["requires-python"], "range", "%s (requires-python)" % manifest)
            for req in proj.get("dependencies") or []:
                p = pep508(req)
                if p:
                    declared.append((p[0], p[1], "runtime", "direct URL requirement" if p[2] else None))
            for group, reqs in (proj.get("optional-dependencies") or {}).items():
                for req in reqs or []:
                    p = pep508(req)
                    if p:
                        declared.append((p[0], p[1], "optional", None))
            for group, reqs in (data.get("dependency-groups") or {}).items():
                for req in reqs or []:
                    if isinstance(req, str):
                        p = pep508(req)
                        if p:
                            declared.append((p[0], p[1], "dev", None))
            tool = data.get("tool") or {}
            poetry = tool.get("poetry") or {}
            for src in poetry.get("source") or []:
                h = host_of(src.get("url"))
                if h and h not in PUBLIC_HOSTS["PyPI"]:
                    sources[src.get("name")] = h
                    if str(src.get("priority", "")).lower() in ("primary", "default") or src.get("default"):
                        self.add_mirror("PyPI", h, "%s ([[tool.poetry.source]] %s)" % (manifest, src.get("name")))
                    else:
                        self.add_private_registry("PyPI", h, "%s ([[tool.poetry.source]] %s)" % (manifest, src.get("name")))

            def poetry_deps(table, scope):
                for name, spec in (table or {}).items():
                    if name.lower() == "python":
                        self.add_runtime("python", spec if isinstance(spec, str) else (spec or {}).get("version"), "range",
                                         "%s (tool.poetry python)" % manifest)
                        continue
                    priv = None
                    if isinstance(spec, dict):
                        if spec.get("path") or spec.get("git") or spec.get("url"):
                            priv = "local, git or URL dependency"
                        elif spec.get("source") in sources:
                            priv = "private source %s" % sources[spec.get("source")]
                        sc = "optional" if spec.get("optional") else scope
                        declared.append((name, spec.get("version"), sc, priv))
                    else:
                        declared.append((name, spec, scope, None))

            poetry_deps(poetry.get("dependencies"), "runtime")
            poetry_deps(poetry.get("dev-dependencies"), "dev")
            for gname, g in (poetry.get("group") or {}).items():
                poetry_deps((g or {}).get("dependencies"), "runtime" if gname == "main" else "dev")
            uv = tool.get("uv") or {}
            for req in uv.get("dev-dependencies") or []:
                p = pep508(req)
                if p:
                    declared.append((p[0], p[1], "dev", None))
            for idx in uv.get("index") or []:
                h = host_of(idx.get("url"))
                if h and h not in PUBLIC_HOSTS["PyPI"]:
                    sources[idx.get("name")] = h
                    if idx.get("default"):
                        self.add_mirror("PyPI", h, "%s ([[tool.uv.index]] %s)" % (manifest, idx.get("name")))
                    else:
                        self.add_private_registry("PyPI", h, "%s ([[tool.uv.index]] %s)" % (manifest, idx.get("name")))
            uv_sources = uv.get("sources") or {}
            for i, (name, spec, scope, priv) in enumerate(declared):
                s = uv_sources.get(name) or uv_sources.get(C.normalize_pypi(name))
                if isinstance(s, dict) and not priv:
                    if s.get("index") in sources:
                        declared[i] = (name, spec, scope, "private index %s" % sources[s["index"]])
                    elif s.get("path") or s.get("git") or s.get("url") or s.get("workspace"):
                        declared[i] = (name, spec, scope, "local, git or workspace dependency")
            pdm = tool.get("pdm") or {}
            for group, reqs in (pdm.get("dev-dependencies") or {}).items():
                for req in reqs or []:
                    p = pep508(req)
                    if p:
                        declared.append((p[0], p[1], "dev", None))
        if "Pipfile" in names:
            pf = self.rel(d, "Pipfile")
            manifest = manifest or pf
            self.note_manifest(pf, "PyPI", "manifest")
            try:
                data = tomllib.loads(self.read(pf))
            except tomllib.TOMLDecodeError as e:
                self.error(pf, "invalid TOML (%s)" % e)
                data = {}
            for src in data.get("source") or []:
                h = host_of(src.get("url"))
                if h and h not in PUBLIC_HOSTS["PyPI"]:
                    self.add_mirror("PyPI", h, "%s ([[source]] %s)" % (pf, src.get("name")))
            req = data.get("requires") or {}
            if req.get("python_full_version") or req.get("python_version"):
                self.add_runtime("python", req.get("python_full_version") or req.get("python_version"),
                                 "exact" if req.get("python_full_version") else "range", "%s (requires)" % pf)
            for key, scope in (("packages", "runtime"), ("dev-packages", "dev")):
                for name, spec in (data.get(key) or {}).items():
                    if isinstance(spec, dict):
                        priv = "local, git or URL dependency" if (spec.get("path") or spec.get("git") or spec.get("file")) else None
                        declared.append((name, spec.get("version"), scope, priv))
                    else:
                        declared.append((name, spec, scope, None))
        if "setup.cfg" in names:
            sc = self.rel(d, "setup.cfg")
            cp = configparser.ConfigParser(interpolation=None)
            try:
                cp.read_string(self.read(sc))
                manifest = manifest or sc
                self.note_manifest(sc, "PyPI", "manifest")
                if cp.has_option("options", "python_requires"):
                    self.add_runtime("python", cp.get("options", "python_requires"), "range", "%s (python_requires)" % sc)
                if cp.has_option("options", "install_requires"):
                    for req in cp.get("options", "install_requires").splitlines():
                        p = pep508(req)
                        if p:
                            declared.append((p[0], p[1], "runtime", None))
                if cp.has_section("options.extras_require"):
                    for _, reqs in cp.items("options.extras_require"):
                        for req in reqs.splitlines():
                            p = pep508(req)
                            if p:
                                declared.append((p[0], p[1], "optional", None))
            except configparser.Error as e:
                self.error(sc, "could not parse (%s)" % e)
        if "setup.py" in names:
            sp = self.rel(d, "setup.py")
            text = self.read(sp, limit=400_000)
            manifest = manifest or sp
            self.note_manifest(sp, "PyPI", "manifest")
            m = re.search(r"python_requires\s*=\s*['\"]([^'\"]+)['\"]", text)
            if m:
                self.add_runtime("python", m.group(1), "range", "%s (python_requires)" % sp)
            m = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.S)
            if m:
                for req in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
                    p = pep508(req)
                    if p:
                        declared.append((p[0], p[1], "runtime", None))
        if lockfile:
            lock_rel = self.rel(d, lockfile)
            self.note_manifest(lock_rel, "PyPI", "lockfile")
            try:
                if lockfile == "poetry.lock":
                    self.parse_poetry_lock(lock_rel, manifest, ws, declared)
                elif lockfile == "uv.lock":
                    self.parse_uv_lock(lock_rel, manifest, ws, declared)
                else:
                    self.parse_pipfile_lock(lock_rel, manifest, ws, declared)
                return
            except Exception as e:
                self.error(lock_rel, "could not parse (%s: %s); using declared ranges" % (type(e).__name__, e))
        unpinned = 0
        for name, spec, scope, priv in declared:
            version, conf, low = C.classify_declared(spec, "PyPI")
            if conf != "exact":
                unpinned += 1
            self.add_lib(ecosystem="PyPI", name=name, version=None if priv else version, confidence="unknown" if priv else conf,
                         direct=True, scope=scope, manifest=manifest, declared=spec, workspace=ws, private=priv, lowest=low)
        if declared and unpinned:
            self.gaps.append("%s: no lockfile; %d dependenc%s with declared ranges only" % (manifest, unpinned, "y" if unpinned == 1 else "ies"))

    def py_graph_add(self, lock_rel, manifest, ws, declared, nodes, deps_of, scope_fallback=None, private_of=None, mirror_of=None):
        """BFS over a Python lockfile graph keyed by normalized name."""
        seen = set()
        order = sorted(declared, key=lambda x: SCOPE_RANK.get(x[2], 9))
        for name, spec, scope, priv in order:
            key = C.normalize_pypi(name)
            if key not in nodes:
                if not priv:
                    version, conf, low = C.classify_declared(spec, "PyPI")
                    self.add_lib(ecosystem="PyPI", name=name, version=version, confidence=conf, direct=True, scope=scope,
                                 manifest=manifest, lockfile=lock_rel, declared=spec, workspace=ws, lowest=low)
                else:
                    self.add_lib(ecosystem="PyPI", name=name, direct=True, scope=scope, manifest=manifest,
                                 lockfile=lock_rel, workspace=ws, private=priv)
                continue
            queue = deque([(key, [], True)])
            while queue:
                k, chain, is_direct = queue.popleft()
                if k in seen:
                    continue
                seen.add(k)
                node = nodes[k]
                p = priv if is_direct and priv else (private_of(k) if private_of else None)
                self.add_lib(ecosystem="PyPI", name=node["name"], version=node["version"], confidence="exact",
                             direct=is_direct, scope=scope, manifest=manifest, lockfile=lock_rel, introduced_by=chain,
                             declared=spec if is_direct else None, workspace=ws, private=p,
                             mirror=mirror_of(k) if mirror_of else None)
                for child in deps_of(k):
                    if child in nodes and child not in seen:
                        queue.append((child, chain + ["%s@%s" % (node["name"], node["version"])], False))
        for k, node in nodes.items():  # anything not reachable from a declared root (e.g. no manifest)
            if k not in seen and not node.get("root"):
                sc = (scope_fallback or {}).get(k, "runtime")
                self.add_lib(ecosystem="PyPI", name=node["name"], version=node["version"], confidence="exact",
                             direct=not declared, scope=sc, manifest=manifest, lockfile=lock_rel, workspace=ws,
                             private=private_of(k) if private_of else None, mirror=mirror_of(k) if mirror_of else None)

    def parse_poetry_lock(self, lock_rel, manifest, ws, declared):
        data = tomllib.loads(self.read(lock_rel))
        nodes, cats, privs = {}, {}, {}
        for p in data.get("package") or []:
            k = C.normalize_pypi(p["name"])
            nodes[k] = {"name": p["name"], "version": p.get("version"), "deps": [C.normalize_pypi(x) for x in (p.get("dependencies") or {})]}
            if p.get("category"):
                cats[k] = "dev" if p["category"] == "dev" else "runtime"
            src = p.get("source") or {}
            if src.get("type") in ("directory", "file", "git", "url"):
                privs[k] = "local, git or URL dependency"
            elif src.get("type") == "legacy" and host_of(src.get("url")) not in PUBLIC_HOSTS["PyPI"]:
                privs[k] = "private source %s" % host_of(src.get("url"))
        self.py_graph_add(lock_rel, manifest, ws, declared, nodes, lambda k: nodes[k]["deps"], cats, privs.get)

    def parse_uv_lock(self, lock_rel, manifest, ws, declared):
        data = tomllib.loads(self.read(lock_rel))
        nodes, privs, mirrors, roots = {}, {}, {}, []
        for p in data.get("package") or []:
            k = C.normalize_pypi(p["name"])
            src = p.get("source") or {}
            deps = [C.normalize_pypi(x["name"]) for x in (p.get("dependencies") or []) if isinstance(x, dict) and x.get("name")]
            node = {"name": p["name"], "version": p.get("version"), "deps": deps}
            if src.get("virtual") or src.get("editable") or src.get("workspace"):
                node["root"] = True
                for x in p.get("dependencies") or []:
                    roots.append((x["name"], None, "runtime", None))
                for _, lst in (p.get("optional-dependencies") or {}).items():
                    for x in lst or []:
                        roots.append((x["name"], None, "optional", None))
                for _, lst in (p.get("dev-dependencies") or {}).items():
                    for x in lst or []:
                        roots.append((x["name"], None, "dev", None))
            elif src.get("path") or src.get("directory") or src.get("git") or src.get("url"):
                privs[k] = "local, git or URL dependency"
            elif src.get("registry"):
                h = host_of(src.get("registry"))
                if h and h not in PUBLIC_HOSTS["PyPI"]:
                    mirrors[k] = h
                    self.add_mirror("PyPI", h, "%s (package source registry)" % lock_rel)
            nodes[k] = node
        decl = {C.normalize_pypi(n): (n, s, sc, pv) for n, s, sc, pv in declared}
        merged = []
        for n, s, sc, pv in roots:
            k = C.normalize_pypi(n)
            if k in decl:
                dn, ds, dsc, dpv = decl[k]
                merged.append((dn, ds, sc if SCOPE_RANK[sc] < SCOPE_RANK.get(dsc, 9) else dsc, dpv))
            else:
                merged.append((n, s, sc, pv))
        merged += [v for k, v in decl.items() if k not in {C.normalize_pypi(r[0]) for r in roots}]
        self.py_graph_add(lock_rel, manifest, ws, merged or declared, nodes, lambda k: nodes[k]["deps"], None,
                          privs.get, mirrors.get)

    def parse_pipfile_lock(self, lock_rel, manifest, ws, declared):
        data = C.load_jsonc(self.read(lock_rel))
        for src in (data.get("_meta") or {}).get("sources") or []:
            h = host_of(src.get("url"))
            if h and h not in PUBLIC_HOSTS["PyPI"]:
                self.add_mirror("PyPI", h, "%s (_meta.sources %s)" % (lock_rel, src.get("name")))
        direct_names = {C.normalize_pypi(n) for n, _, _, _ in declared}
        privs = {C.normalize_pypi(n): pv for n, _, _, pv in declared if pv}
        for key, scope in (("default", "runtime"), ("develop", "dev")):
            for name, info in (data.get(key) or {}).items():
                info = info or {}
                version = str(info.get("version") or "").lstrip("=") or None
                priv = privs.get(C.normalize_pypi(name))
                if info.get("path") or info.get("git") or info.get("file") or info.get("editable"):
                    priv = priv or "local, git or URL dependency"
                self.add_lib(ecosystem="PyPI", name=name, version=version, confidence="exact" if version else "unknown",
                             direct=C.normalize_pypi(name) in direct_names or not direct_names, scope=scope,
                             manifest=manifest, lockfile=lock_rel, workspace=ws, private=priv)

    # ------------------------------------------------------------------ Maven
    def do_maven(self, d, names):
        if "pom.xml" in names:
            self.parse_pom(self.rel(d, "pom.xml"), d or ".")
        for sname in ("settings.xml",):
            for cand in (self.rel(d, sname), self.rel(d, ".mvn/" + sname)):
                if self.exists(cand) and cand not in getattr(self, "_settings_seen", set()):
                    self._settings_seen = getattr(self, "_settings_seen", set()) | {cand}
                    self.parse_maven_settings(cand)

    def parse_maven_settings(self, rel):
        try:
            root = parse_xml_file(self.root / rel)
        except Exception as e:
            self.error(rel, "could not parse (%s)" % e)
            return
        if root.tag != "settings":
            return
        for mirror in root.iter("mirror"):
            url = (mirror.findtext("url") or "").strip()
            of = (mirror.findtext("mirrorOf") or "").strip()
            h = host_of(url)
            if h and h not in PUBLIC_HOSTS["Maven"] and ("*" in of or "central" in of):
                self.add_mirror("Maven", h, "%s (mirror of %s)" % (rel, of))
                self.maven_private.append("%s: mirror %s" % (rel, h))
        for server in root.iter("server"):
            if server.findtext("password") or server.findtext("privateKey"):
                self.add_private_registry("Maven", server.findtext("id") or "(server)", rel,
                                          credential="%s in <server> at %s" % (C.redact_token(server.findtext("password") or ""), rel))

    def pom_model(self, rel, depth=0):
        root = parse_xml_file(self.root / rel)
        props = {}
        parent = root.find("parent")
        parent_model = None
        if parent is not None and depth < 6:
            rp = parent.findtext("relativePath")
            rp = "../pom.xml" if rp is None else rp.strip()
            if rp:
                base = rel.rsplit("/", 1)[0] if "/" in rel else ""
                cand = norm_rel(base, rp)
                if not cand.endswith(".xml"):
                    cand = norm_rel(cand, "pom.xml")
                if self.exists(cand) and cand != rel:
                    try:
                        parent_model = self.pom_model(cand, depth + 1)
                    except Exception:
                        parent_model = None
        if parent_model:
            props.update(parent_model["props"])
        el = root.find("properties")
        if el is not None:
            for child in el:
                if isinstance(child.tag, str):
                    props[child.tag] = (child.text or "").strip()
        gid = root.findtext("groupId") or (parent.findtext("groupId") if parent is not None else None)
        ver = root.findtext("version") or (parent.findtext("version") if parent is not None else None)
        props.update({"project.groupId": gid, "pom.groupId": gid, "project.version": ver, "pom.version": ver,
                      "version": ver, "project.artifactId": root.findtext("artifactId")})
        if parent is not None:
            props.update({"project.parent.version": parent.findtext("version"), "parent.version": parent.findtext("version")})
        managed = dict(parent_model["managed"]) if parent_model else {}
        dm = root.find("dependencyManagement")
        boms = list(parent_model["boms"]) if parent_model else []
        if dm is not None:
            for dep in dm.iter("dependency"):
                g, a, v = dep.findtext("groupId"), dep.findtext("artifactId"), dep.findtext("version")
                if (dep.findtext("scope") or "") == "import":
                    boms.append((g, a, v))
                elif g and a:
                    managed["%s:%s" % (g, a)] = v
        return {"root": root, "props": props, "managed": managed, "boms": boms, "parent": parent,
                "groupId": gid, "parent_model": parent_model}

    def interp(self, value, props, depth=0):
        if value is None:
            return None
        value = value.strip()
        if "${" not in value or depth > 5:
            return value if "${" not in value else None
        out = re.sub(r"\$\{([^}]+)\}", lambda m: str(props.get(m.group(1))) if props.get(m.group(1)) is not None else m.group(0), value)
        return self.interp(out, props, depth + 1) if out != value else (out if "${" not in out else None)

    def parse_pom(self, rel, ws):
        try:
            model = self.pom_model(rel)
        except Exception as e:
            self.error(rel, "could not parse (%s)" % e)
            return
        self.note_manifest(rel, "Maven", "manifest")
        root, props = model["root"], model["props"]
        self.scan_leads(rel, self.read(rel))
        for key in ("maven.compiler.release", "maven.compiler.target", "maven.compiler.source", "java.version", "release"):
            v = self.interp(props.get(key), props)
            if v:
                self.add_runtime("java", v, "exact", "%s (%s)" % (rel, key))
                break
        for plugin in root.iter("plugin"):
            if plugin.findtext("artifactId") == "maven-compiler-plugin":
                conf = plugin.find("configuration")
                if conf is not None:
                    for k in ("release", "target", "source"):
                        v = self.interp(conf.findtext(k), props)
                        if v:
                            self.add_runtime("java", v, "exact", "%s (maven-compiler-plugin %s)" % (rel, k))
                            break
        public_repo = True
        for repo in list(root.iter("repository")) + list(root.iter("pluginRepository")):
            url = repo.findtext("url") or ""
            h = host_of(self.interp(url, props) or url)
            if h and h not in PUBLIC_HOSTS["Maven"]:
                public_repo = False
                self.add_private_registry("Maven", h, "%s (<repositories>)" % rel)
                self.maven_private.append("%s: repository %s" % (rel, h))
        own_group = model["groupId"] or ""
        own_prefix = ".".join(own_group.split(".")[:2]) if own_group.count(".") >= 1 else own_group
        parent = model["parent"]
        boot_version = None
        if parent is not None:
            pg, pa, pv = parent.findtext("groupId"), parent.findtext("artifactId"), self.interp(parent.findtext("version"), props)
            if pg and pa and pv and pg in ("org.springframework.boot", "io.quarkus"):
                boot_version = (pg, pv)
        for g, a, v in model["boms"]:
            v = self.interp(v, props)
            if g in ("org.springframework.boot", "io.quarkus") and v:
                boot_version = (g, v)
        deps_el = root.find("dependencies")
        if deps_el is None:
            if boot_version:
                g, v = boot_version
                art = "spring-boot" if g == "org.springframework.boot" else "quarkus-core"
                self.add_lib(ecosystem="Maven", name="%s:%s" % (g, art), version=v, confidence="exact", direct=True,
                             scope="runtime", manifest=rel, workspace=ws, declared="parent/BOM %s" % v)
            return
        for dep in deps_el.findall("dependency"):
            g = self.interp(dep.findtext("groupId"), props)
            a = self.interp(dep.findtext("artifactId"), props)
            if not g or not a:
                continue
            raw_v = dep.findtext("version")
            v = self.interp(raw_v, props) if raw_v else None
            if v is None and raw_v is None:
                mv = model["managed"].get("%s:%s" % (g, a))
                v = self.interp(mv, props) if mv else None
                if v is None and boot_version and g == boot_version[0]:
                    v = boot_version[1]
            scope_raw = (dep.findtext("scope") or "compile").strip()
            scope = {"test": "dev", "provided": "build", "system": "build"}.get(scope_raw, "runtime")
            if (dep.findtext("optional") or "").strip() == "true":
                scope = "optional" if scope == "runtime" else scope
            version, conf, low = C.classify_declared(v, "Maven") if v else (None, "unknown", None)
            if version is None:
                self.maven_unknown_versions += 1
            priv = None
            if scope_raw == "system":
                priv = "system-scoped local JAR"
            elif not public_repo and own_prefix and g.startswith(own_prefix):
                priv = "internal groupId %s served by a private repository" % own_prefix
            self.add_lib(ecosystem="Maven", name="%s:%s" % (g, a), version=version, confidence=conf, direct=True,
                         scope=scope, manifest=rel, declared=raw_v, workspace=ws, private=priv, lowest=low)
        if not getattr(self, "_maven_gap_noted", False):
            self._maven_gap_noted = True
            self.gaps.append("Maven: transitive dependencies of pom.xml are not resolved by this skill; osv-scanner resolves them when it is allowed to run")

    # ------------------------------------------------------------------ Gradle
    # Dependency configurations: the standard ones, any variant/flavor/source-set prefixed form
    # (releaseImplementation, freeDebugApi, androidTestImplementation, kspAndroidTest, ...) and the
    # Android-specific ones. `classpath` covers legacy buildscript { dependencies { ... } } plugins.
    GRADLE_CONF = (r"\b((?:[a-z][A-Za-z0-9]*)?(?:Implementation|Api|CompileOnly|RuntimeOnly|AnnotationProcessor)"
                   r"|implementation|api|compile|runtime|compileOnly|runtimeOnly|annotationProcessor"
                   r"|testCompile|testCompileOnly|testRuntimeOnly|(?:kapt|ksp)(?:[A-Z][A-Za-z0-9]*)?"
                   r"|developmentOnly|coreLibraryDesugaring|lintChecks|lintPublish|classpath)")
    # Plugin id -> the Maven artifact that holds it, so the vulnerability and support checks look up
    # a real library. Ids not listed here use the Gradle plugin marker artifact <id>:<id>.gradle.plugin.
    GRADLE_PLUGIN_ARTIFACTS = [
        (r"com\.android\.(application|library|test|dynamic-feature|asset-pack|kotlin\.multiplatform\.library)$", "com.android.tools.build:gradle"),
        (r"org\.jetbrains\.kotlin\.plugin\.serialization$", "org.jetbrains.kotlin:kotlin-serialization"),
        (r"org\.jetbrains\.kotlin\.plugin\.compose$", "org.jetbrains.kotlin:compose-compiler-gradle-plugin"),
        (r"org\.jetbrains\.kotlin\..+", "org.jetbrains.kotlin:kotlin-gradle-plugin"),
        (r"com\.google\.devtools\.ksp$", "com.google.devtools.ksp:symbol-processing-gradle-plugin"),
        (r"com\.google\.gms\.google-services$", "com.google.gms:google-services"),
        (r"com\.google\.firebase\.crashlytics$", "com.google.firebase:firebase-crashlytics-gradle"),
        (r"com\.google\.dagger\.hilt\.android$", "com.google.dagger:hilt-android-gradle-plugin"),
        (r"androidx\.navigation\.safeargs(\.kotlin)?$", "androidx.navigation:navigation-safe-args-gradle-plugin"),
        (r"androidx\.room$", "androidx.room:room-gradle-plugin"),
    ]

    @staticmethod
    def gradle_alias(accessor):
        """Gradle treats -, _ and . in catalog aliases as the same separator."""
        return re.sub(r"[-_.]", ".", accessor).lower()

    @staticmethod
    def gradle_blocks(text, name):
        """The bodies of every `name { ... }` block, braces balanced."""
        out = []
        for m in re.finditer(r"\b%s\s*\{" % name, text):
            depth, i = 1, m.end()
            while i < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[i], 0)
                i += 1
            out.append(text[m.end():i - 1])
        return out

    def gradle_plugin_artifact(self, pid):
        for pat, artifact in self.GRADLE_PLUGIN_ARTIFACTS:
            if re.match(pat, pid):
                return artifact
        return "%s:%s.gradle.plugin" % (pid, pid)

    def gradle_vars(self, d, catalog):
        """Version variables a build file can use: gradle.properties (root, then the module's own),
        ext/extra properties and local val/var/def strings in the root and module build files, and the
        catalog's [versions] as libs.versions.<alias>. Later sources override earlier ones."""
        out = {}
        for rel in C.dedupe(["gradle.properties", self.rel(d, "gradle.properties")]):
            if self.exists(rel):
                for line in self.read(rel).splitlines():
                    m = re.match(r"\s*([\w.\-]+)\s*[=:]\s*(\S.*?)\s*$", line)
                    if m and not line.lstrip().startswith(("#", "!")):
                        out[m.group(1)] = m.group(2)
        files = []
        for n in ("build.gradle", "build.gradle.kts"):
            for rel in C.dedupe([n, self.rel(d, n)]):
                if self.exists(rel) and rel not in files:
                    files.append(rel)
        q = r"['\"]([^'\"$]+)['\"]"
        pats = [r"\bext\.(\w+)\s*=\s*" + q,                                  # ext.kotlin_version = '1.9.0'
                r"\bextra\[\s*['\"](\w+)['\"]\s*\]\s*=\s*" + q,              # extra["x"] = "1"
                r"\bset\(\s*['\"](\w+)['\"]\s*,\s*" + q + r"\s*\)",          # extra.set("x", "1")
                r"\bva[lr]\s+(\w+)\s+by\s+extra\(\s*" + q + r"\s*\)",        # val x by extra("1")
                r"\b(?:val|var|def|String)\s+(\w+)\s*(?::\s*String)?\s*=\s*" + q]
        for rel in files:
            text = self.read(rel, limit=1_000_000)
            for block in self.gradle_blocks(text, "ext"):
                for m in re.finditer(r"^\s*(?:set\(\s*['\"])?(\w+)['\"]?\s*(?:=|,)\s*" + q, block, re.M):
                    out[m.group(1)] = m.group(2)
            for p in pats:
                for m in re.finditer(p, text):
                    out[m.group(1)] = m.group(2)
        for alias, v in catalog.get("versions", {}).items():
            out["libs.versions." + alias] = v
        return out

    @staticmethod
    def gradle_subst(value, variables):
        """Fill $name, ${name}, ${rootProject.ext.name}, ${libs.versions.x.get()} and the like; None
        when a reference stays unresolved."""
        if value is None or "$" not in value:
            return value

        def look(name):
            name = re.sub(r"^(?:rootProject\.|project\.)?(?:ext\.|extra\.|properties\.)?", "", name)
            name = re.sub(r"^extra\[\s*['\"](\w+)['\"]\s*\]$", r"\1", name)
            name = re.sub(r"\.get\(\)$", "", name)
            if name.startswith("libs.versions."):
                name = "libs.versions." + Inventory.gradle_alias(name[len("libs.versions."):])
            return variables.get(name)

        out = re.sub(r"\$\{([^}]+)\}|\$([A-Za-z_]\w*)", lambda m: look((m.group(1) or m.group(2)).strip()) or m.group(0), value)
        return None if "$" in out else out

    def do_gradle(self, d, names):
        builds = [n for n in names if n in ("build.gradle", "build.gradle.kts")]
        settings = [n for n in names if n in ("settings.gradle", "settings.gradle.kts")]
        lock = "gradle.lockfile" if "gradle.lockfile" in names else None
        if not builds and not lock:
            return
        ws = d or "."
        catalog = {"libraries": {}, "bundles": {}, "plugins": {}, "versions": {}}
        for cat_rel in (self.rel(d, "gradle/libs.versions.toml"), "gradle/libs.versions.toml"):
            if self.exists(cat_rel):
                catalog = self.gradle_catalog(cat_rel)
                break
        variables = self.gradle_vars(d, catalog)

        def sub(v):
            return self.gradle_subst(v, variables)

        wrapper = self.rel(d, "gradle/wrapper/gradle-wrapper.properties")
        if self.exists(wrapper):
            m = re.search(r"distributionUrl\s*=.*?gradle-(\d+(?:\.\d+)*(?:-[\w.]+)?)-(?:bin|all)\.zip", self.read(wrapper))
            if m:
                self.add_runtime("gradle", m.group(1), "exact", "%s (Gradle wrapper)" % wrapper)
        declared = {}
        plugins = {}   # artifact -> (version, plugin id, file)
        applied = set()  # plugin ids this module applies (not "apply false")
        boms = []
        manifest = None
        boot = None
        android = False
        conf_re = self.GRADLE_CONF
        plat = r"\s*\(?\s*((?:enforced)?[pP]latform\s*\(?\s*)?"
        ver_re = r"(?:\s*version\s*\(?\s*(?:['\"]([^'\"]+)['\"]|(libs\.versions\.[\w.]+?)(?:\.get\(\))?|([A-Za-z_]\w*))\s*\)?)?"
        for b in settings + builds:
            rel = self.rel(d, b)
            text = self.read(rel, limit=1_000_000)
            is_build = b in builds
            if is_build:
                manifest = rel
                self.note_manifest(rel, "Maven", "manifest")
                self.scan_leads(rel, text)
            for mm in re.finditer(r"maven\s*\{[^}]*?url\s*(?:=\s*)?(?:uri\s*\()?\s*['\"]([^'\"]+)['\"]", text, re.S):
                h = host_of(mm.group(1))
                if h and h not in PUBLIC_HOSTS["Maven"]:
                    self.add_private_registry("Maven", h, "%s (repositories)" % rel)
                    self.maven_private.append("%s: repository %s" % (rel, h))
            for block in self.gradle_blocks(text, "plugins"):
                for mm in re.finditer(r"(?:\bid\s*\(?\s*['\"]([\w.\-]+)['\"]|\bkotlin\s*\(\s*['\"]([\w.\-]+)['\"])\s*\)?" + ver_re, block):
                    pid = mm.group(1) or "org.jetbrains.kotlin." + mm.group(2)
                    android = android or pid.startswith("com.android.")
                    v = mm.group(3) or (("${%s}" % mm.group(4)) if mm.group(4) else None) or \
                        (("${%s}" % mm.group(5)) if mm.group(5) and mm.group(5) not in ("apply", "false", "true") else None)
                    v = sub(v)
                    if is_build and not re.match(r"\s*\)?\s*apply\s*\(?\s*false", block[mm.end():]):
                        applied.add(pid)
                    if v:
                        plugins[self.gradle_plugin_artifact(pid)] = (v, pid, rel)
                for mm in re.finditer(r"\balias\s*\(?\s*libs\.plugins\.([\w.]+)", block):
                    ent = catalog["plugins"].get(self.gradle_alias(mm.group(1)))
                    if ent:
                        android = android or ent[0].startswith("com.android.")
                        if is_build and not re.match(r"[\w.]*\s*\)?\s*apply\s*\(?\s*false", block[mm.end():]):
                            applied.add(ent[0])
                        if ent[1]:
                            plugins[self.gradle_plugin_artifact(ent[0])] = (ent[1], ent[0], rel)
            if not is_build:
                continue
            # fill ${...} templates first: one like ${rootProject.extra["v"]} holds quotes of its own
            text = re.sub(r"\$\{[^{}\n]+\}", lambda m: sub(m.group(0)) or m.group(0), text)
            android = android or bool(re.search(r"apply\s+plugin\s*:\s*['\"]com\.android\.", text))
            for mm in re.finditer(r"apply\s*\(?\s*plugin\s*[:=]\s*['\"]([\w.\-]+)['\"]", text):   # legacy plugin application
                legacy = {"kotlin-android": "org.jetbrains.kotlin.android", "kotlin": "org.jetbrains.kotlin.jvm",
                          "kotlin-multiplatform": "org.jetbrains.kotlin.multiplatform"}
                applied.add(legacy.get(mm.group(1), mm.group(1)))
            # kotlin("test") / kotlin("reflect", "1.9.0"): org.jetbrains.kotlin:kotlin-<name>, versioned by the plugin
            for mm in re.finditer(conf_re + r"\s*\(?\s*kotlin\(\s*['\"]([\w\-]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?\s*\)", text):
                declared["org.jetbrains.kotlin:kotlin-%s" % mm.group(2)] = (sub(mm.group(3)) or "$kotlin-plugin", mm.group(1))
            m = re.search(r"id\s*\(?\s*['\"]org\.springframework\.boot['\"]\s*\)?\s*version\s*\(?\s*['\"]([^'\"]+)['\"]", text)
            if m:
                boot = m.group(1)
            # The JDK: a toolchain names the JDK the build runs on. sourceCompatibility and jvmTarget only
            # set the bytecode level; on Android that is not a JVM the app runs on, so it is not recorded.
            m = re.search(r"(?:languageVersion\s*(?:=|\.set\()\s*JavaLanguageVersion\.of\(\s*|jvmToolchain\s*\(\s*)(\d+)", text)
            if m:
                self.add_runtime("java", m.group(1), "exact", "%s (JDK toolchain)" % rel)
            elif "android {" not in text and not android:
                m = re.search(r"sourceCompatibility\s*=\s*(?:JavaVersion\.VERSION_|['\"]?)(1[._]\d|\d+)", text)
                if m:
                    self.add_runtime("java", m.group(1).replace("_", "."), "exact", "%s (toolchain)" % rel)
            if "android {" in text or re.search(r"\bandroid\s*\{", text):
                android = True
                levels = {}
                for key in ("minSdk", "targetSdk", "compileSdk"):
                    mm = re.search(r"\b%s(?:Version)?\s*(?:=\s*|\(\s*|\s+)(?:(\d+)|libs\.versions\.([\w.]+?)(?:\.get\(\))?(?:\.toInt\(\))?\b|([A-Za-z_]\w*))" % key, text)
                    if not mm:
                        continue
                    val = mm.group(1) or (variables.get("libs.versions." + self.gradle_alias(mm.group(2))) if mm.group(2) else None) \
                        or (variables.get(mm.group(3)) if mm.group(3) else None)
                    if val and str(val).strip().isdigit():
                        levels[key] = str(val).strip()
                if levels.get("minSdk"):
                    others = ", ".join("%s %s" % (k, levels[k]) for k in ("targetSdk", "compileSdk") if k in levels)
                    self.add_runtime("android", levels["minSdk"], "exact",
                                     "%s (minSdk %s%s)" % (rel, levels["minSdk"], ("; " + others) if others else ""))
            for mm in re.finditer(conf_re + plat + r"['\"]([^'\":]+):([^'\":]+)(?::([^'\"@:]+))?[^'\"]*['\"]", text):
                key = "%s:%s" % (mm.group(3), mm.group(4))
                declared[key] = (sub(mm.group(5)), mm.group(1))
                if mm.group(2):
                    boms.append(key)
            for mm in re.finditer(conf_re + r"\s*\(?\s*group\s*[:=]\s*['\"]([^'\"]+)['\"]\s*,\s*name\s*[:=]\s*['\"]([^'\"]+)['\"](?:\s*,\s*version\s*[:=]\s*['\"]([^'\"]+)['\"])?", text):
                declared["%s:%s" % (mm.group(2), mm.group(3))] = (sub(mm.group(4)), mm.group(1))
            for mm in re.finditer(conf_re + plat + r"libs\.([\w.]+)", text):
                accessor = self.gradle_alias(mm.group(3))
                if accessor.startswith("bundles."):
                    aliases = catalog["bundles"].get(accessor[len("bundles."):], [])
                else:
                    aliases = [accessor]
                for alias in aliases:
                    ent = catalog["libraries"].get(alias)
                    if ent:
                        declared[ent[0]] = (ent[1], mm.group(1))
                        if mm.group(2):
                            boms.append(ent[0])
        kotlin_plugin_v = plugins.get("org.jetbrains.kotlin:kotlin-gradle-plugin", (None,))[0] or \
            next((r["version"] for r in self.runtimes.values() if r["runtime"] == "kotlin" and r["version"]), None)
        for key, (v, conf_name) in list(declared.items()):
            if v == "$kotlin-plugin":
                declared[key] = (kotlin_plugin_v, conf_name)
            elif v and "$" in v:
                declared[key] = (None, conf_name)
            elif not v and boot and key.startswith("org.springframework.boot:"):
                declared[key] = (boot, conf_name)

        def gscope(conf_name):
            c = conf_name.lower()
            if "test" in c:
                return "dev"
            if (c.endswith(("compileonly", "annotationprocessor")) or c.startswith(("kapt", "ksp"))
                    or c in ("developmentonly", "lintchecks", "lintpublish", "classpath")):
                return "build"
            return "runtime"

        if boot and not any(k.startswith("org.springframework.boot:") for k in declared):
            declared["org.springframework.boot:spring-boot"] = (boot, "implementation")
        # Kotlin: the Kotlin Gradle plugin's version is the Kotlin version the build compiles with.
        for artifact, (v, pid, rel) in plugins.items():
            if pid.startswith("org.jetbrains.kotlin.") and artifact == "org.jetbrains.kotlin:kotlin-gradle-plugin":
                self.add_runtime("kotlin", v, C.classify_declared(v, "Maven")[1], "%s (plugin %s)" % (rel, pid))
        for key, (v, conf_name) in declared.items():
            if key in ("org.jetbrains.kotlin:kotlin-gradle-plugin", "org.jetbrains.kotlin:kotlin-stdlib") and v:
                self.add_runtime("kotlin", v, C.classify_declared(v, "Maven")[1], "%s (%s)" % (manifest, key))
        # Plugins are build tooling and are not in gradle.lockfile, so they are always recorded from
        # their declared versions. The Spring Boot plugin is already covered above. A plugin declared
        # in the root project and applied again in each module is recorded once.
        seen = self.gradle_plugins_seen
        for artifact, (v, pid, rel) in plugins.items():
            if pid == "org.springframework.boot" or artifact in declared or (artifact, v) in seen:
                continue
            seen.add((artifact, v))
            version, conf, low = C.classify_declared(v, "Maven")
            self.add_lib(ecosystem="Maven", name=artifact, version=version, confidence=conf, direct=True,
                         scope="build", manifest=rel, declared=v, workspace=ws, lowest=low,
                         lookup_note="Gradle plugin %s" % pid)
        if lock:
            lock_rel = self.rel(d, lock)
            self.note_manifest(lock_rel, "Maven", "lockfile")
            for line in self.read(lock_rel).splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("empty="):
                    continue
                m = re.match(r"^([^:]+):([^:]+):([^=]+)=(.*)$", line)
                if not m:
                    continue
                g, a, v, confs = m.groups()
                cl = confs.lower()
                if "runtimeclasspath" in cl or "compileclasspath" in cl and "test" not in cl:
                    scope = "runtime"
                elif "test" in cl:
                    scope = "dev"
                else:
                    scope = "build"
                key = "%s:%s" % (g, a)
                self.add_lib(ecosystem="Maven", name=key, version=v, confidence="exact", direct=key in declared,
                             scope=scope, manifest=manifest, lockfile=lock_rel, workspace=ws)
            return
        entries = []
        for key, (v, conf_name) in declared.items():
            # spec §9: declared versions, "range" unless they're exact
            version, conf, low = C.classify_declared(v, "Maven") if v else (None, "unknown", None)
            note = None
            if not v and boms and key not in boms:
                note = "version managed by BOM %s (not resolved)" % ", ".join(sorted(set(boms)))
            lib = self.add_lib(ecosystem="Maven", name=key, version=version, confidence=conf, direct=True,
                               scope=gscope(conf_name), manifest=manifest, declared=v, workspace=ws, lowest=low,
                               lookup_note=note)
            if lib is not None:
                entries.append((lib, key, v, key in boms))
        # The Kotlin plugin adds kotlin-stdlib at its own version unless kotlin.stdlib.default.dependency=false.
        implicit = []
        kotlin_applied = any(re.match(r"org\.jetbrains\.kotlin\.(android|jvm|multiplatform)$", p) for p in applied)
        if kotlin_applied and str(variables.get("kotlin.stdlib.default.dependency", "true")).strip().lower() != "false":
            kv = plugins.get("org.jetbrains.kotlin:kotlin-gradle-plugin", (None,))[0]
            if not kv:
                known = [r["version"] for r in self.runtimes.values() if r["runtime"] == "kotlin" and r["version"]]
                kv = max(known, key=C.version_sort_key) if known else None
            if kv:
                implicit.append(("org.jetbrains.kotlin:kotlin-stdlib", kv))
        align = []
        if kotlin_applied and implicit and \
                str(variables.get("kotlin.stdlib.jdk.variants.version.alignment", "true")).strip().lower() != "false":
            align = [("org.jetbrains.kotlin:kotlin-stdlib-jdk7", implicit[0][1]), ("org.jetbrains.kotlin:kotlin-stdlib-jdk8", implicit[0][1])]
        if builds and declared:
            # resolve_gradle() replaces this gap when it resolves the build online
            gap = "%s: no gradle.lockfile; declared versions only, transitive dependencies not resolved" % manifest
            self.gaps.append(gap)
            self.gradle_builds.append({"manifest": manifest, "workspace": ws, "entries": entries, "gap": gap,
                                       "implicit": implicit, "align": align})

    def gradle_catalog(self, rel):
        """libs.versions.toml as {"libraries": {alias: (module, version)}, "bundles": {alias: [library
        aliases]}, "plugins": {alias: (plugin id, version)}, "versions": {alias: version}}, aliases
        normalised by gradle_alias."""
        out = {"libraries": {}, "bundles": {}, "plugins": {}, "versions": {}}
        try:
            data = tomllib.loads(self.read(rel))
        except tomllib.TOMLDecodeError as e:
            self.error(rel, "invalid TOML (%s)" % e)
            return out
        versions = data.get("versions") or {}

        def version_of(v):
            if isinstance(v, dict):
                v = versions.get(v.get("ref")) if v.get("ref") else (v.get("strictly") or v.get("require") or v.get("prefer"))
            if isinstance(v, dict):
                v = v.get("strictly") or v.get("require") or v.get("prefer")
            return v if isinstance(v, str) else None

        for alias, spec in (data.get("libraries") or {}).items():
            alias = self.gradle_alias(alias)
            if isinstance(spec, str):
                parts = spec.split(":")
                if len(parts) >= 2:
                    out["libraries"][alias] = ("%s:%s" % (parts[0], parts[1]), parts[2] if len(parts) > 2 else None)
                continue
            if not isinstance(spec, dict):
                continue
            module = spec.get("module") or ("%s:%s" % (spec.get("group"), spec.get("name")) if spec.get("group") else None)
            if module:
                out["libraries"][alias] = (module, version_of(spec.get("version")))
        for alias, v in versions.items():
            v = version_of(v) if isinstance(v, dict) else v
            if isinstance(v, str):
                out["versions"][self.gradle_alias(alias)] = v
        for alias, members in (data.get("bundles") or {}).items():
            if isinstance(members, list):
                out["bundles"][self.gradle_alias(alias)] = [self.gradle_alias(m) for m in members if isinstance(m, str)]
        for alias, spec in (data.get("plugins") or {}).items():
            alias = self.gradle_alias(alias)
            if isinstance(spec, str):
                pid, _, v = spec.partition(":")
                out["plugins"][alias] = (pid, v or None)
            elif isinstance(spec, dict) and spec.get("id"):
                out["plugins"][alias] = (spec["id"], version_of(spec.get("version")))
        return out

    # ------------------------------------------------------------------ Go
    def go_private(self, module):
        for pat in self.go_private_patterns:
            if fnmatch.fnmatch(module, pat) or fnmatch.fnmatch(module, pat + "/*") or module.startswith(pat.rstrip("/*") + "/"):
                return "matches GOPRIVATE/GONOPROXY pattern %s" % pat
        host = module.split("/", 1)[0].lower()
        if self.remote_host and host == self.remote_host and host not in PUBLIC_GO_HOSTS:
            return "hosted on the project's own git server (%s)" % host
        if private_host(host):
            return "module path on a private network host (%s)" % host
        return None

    def do_go(self, d, names):
        if "go.mod" not in names:
            return
        rel = self.rel(d, "go.mod")
        ws = d or "."
        text = self.read(rel)
        self.note_manifest(rel, "Go", "manifest")
        self.go_modules.append(rel)
        lock_rel = self.rel(d, "go.sum") if "go.sum" in names else None
        if lock_rel:
            self.note_manifest(lock_rel, "Go", "lockfile")
        replaces, requires = {}, []
        block = None
        for raw in text.splitlines():
            line = raw.split("//", 1)[0].strip()
            comment = raw.split("//", 1)[1].strip() if "//" in raw else ""
            if not line:
                continue
            if line.endswith("(") and line.split()[0] in ("require", "replace", "exclude", "retract", "tool", "godebug"):
                block = line.split()[0]
                continue
            if line == ")":
                block = None
                continue
            words = line.split()
            kind = block
            if not block:
                kind, words = words[0], words[1:]
            if kind == "go" and words:
                self.add_runtime("go", words[0], "range", "%s (go directive)" % rel)
            elif kind == "toolchain" and words:
                self.add_runtime("go", words[0].replace("go", "", 1), "exact", "%s (toolchain)" % rel)
            elif kind == "require" and len(words) >= 2:
                requires.append((words[0], words[1], "indirect" in comment))
            elif kind == "replace" and "=>" in words:
                i = words.index("=>")
                old, new = words[:i], words[i + 1:]
                replaces[old[0]] = new
        for mod, ver, indirect in requires:
            name, version, priv = mod, ver, None
            if mod in replaces:
                new = replaces[mod]
                if new and (new[0].startswith(".") or new[0].startswith("/")):
                    priv = "replaced by local path %s" % new[0]
                    version = None
                elif len(new) >= 2:
                    name, version = new[0], new[1]
            if version and re.match(r"^v\d", version):
                version = version[1:]  # OSV.dev and osv-scanner write Go versions without the "v"
            priv = priv or self.go_private(name)
            self.add_lib(ecosystem="Go", name=name, version=version, confidence="exact" if version else "unknown",
                         direct=not indirect, scope="runtime", manifest=rel, lockfile=lock_rel, workspace=ws, private=priv)

    # ------------------------------------------------------------------ Cargo
    def do_cargo(self, d, names):
        if "Cargo.toml" not in names and "Cargo.lock" not in names:
            return
        ws = d or "."
        if ws in self.cargo_covered and "Cargo.lock" not in names:
            return
        manifest = self.rel(d, "Cargo.toml") if "Cargo.toml" in names else None
        declared, members = {}, []
        registries_private = {}
        for cfg in (self.rel(d, ".cargo/config.toml"), self.rel(d, ".cargo/config")):
            if self.exists(cfg):
                try:
                    c = tomllib.loads(self.read(cfg))
                except tomllib.TOMLDecodeError:
                    continue
                for rname, r in (c.get("registries") or {}).items():
                    h = host_of(str(r.get("index", "")).replace("sparse+", ""))
                    registries_private[rname] = h
                    self.add_private_registry("crates.io", h or rname, cfg)
                src = (c.get("source") or {})
                cio = src.get("crates-io") or {}
                if cio.get("replace-with"):
                    target = src.get(cio["replace-with"]) or {}
                    h = host_of(str(target.get("registry", "")).replace("sparse+", "")) or cio["replace-with"]
                    self.add_mirror("crates.io", h, "%s (source.crates-io replace-with)" % cfg)
        if manifest:
            self.note_manifest(manifest, "crates.io", "manifest")
            try:
                data = tomllib.loads(self.read(manifest))
            except tomllib.TOMLDecodeError as e:
                self.error(manifest, "invalid TOML (%s)" % e)
                data = {}
            pkg = data.get("package") or {}
            rv = pkg.get("rust-version")
            if isinstance(rv, str):
                self.add_runtime("rust", rv, "range", "%s (rust-version)" % manifest)
            wsdeps = (data.get("workspace") or {}).get("dependencies") or {}

            def collect(table, scope):
                for name, spec in (table or {}).items():
                    if isinstance(spec, dict) and spec.get("workspace"):
                        spec = wsdeps.get(name, spec)
                    priv = None
                    if isinstance(spec, dict):
                        if spec.get("path") or spec.get("git"):
                            priv = "local or git dependency"
                        elif spec.get("registry"):
                            priv = "private registry %s" % spec.get("registry")
                        real = spec.get("package") or name
                        sc = "optional" if spec.get("optional") and scope == "runtime" else scope
                        declared[real] = (spec.get("version"), sc, priv)
                    else:
                        declared[name] = (spec, scope, None)

            collect(data.get("dependencies"), "runtime")
            collect(data.get("dev-dependencies"), "dev")
            collect(data.get("build-dependencies"), "build")
            for _, t in (data.get("target") or {}).items():
                collect((t or {}).get("dependencies"), "runtime")
                collect((t or {}).get("dev-dependencies"), "dev")
                collect((t or {}).get("build-dependencies"), "build")
            collect(wsdeps, "runtime") if not data.get("package") else None
            for pat in (data.get("workspace") or {}).get("members") or []:
                for f in self.files:
                    if f.endswith("/Cargo.toml"):
                        mdir = f[: -len("/Cargo.toml")]
                        sub = mdir[len(d) + 1:] if d else mdir
                        if (not d or mdir.startswith(d + "/")) and fnmatch.fnmatch(sub, pat):
                            members.append(mdir)
                            self.cargo_covered.add(mdir)
                            try:
                                md = tomllib.loads(self.read(f))
                                for key, scope in (("dependencies", "runtime"), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
                                    for name, spec in (md.get(key) or {}).items():
                                        if isinstance(spec, dict) and spec.get("workspace"):
                                            spec = wsdeps.get(name, spec)
                                        if isinstance(spec, dict):
                                            if spec.get("path"):
                                                continue
                                            declared.setdefault(spec.get("package") or name, (spec.get("version"), scope, "private registry" if spec.get("registry") else None))
                                        else:
                                            declared.setdefault(name, (spec, scope, None))
                            except tomllib.TOMLDecodeError:
                                pass
        if "Cargo.lock" in names:
            lock_rel = self.rel(d, "Cargo.lock")
            self.note_manifest(lock_rel, "crates.io", "lockfile")
            data = tomllib.loads(self.read(lock_rel))
            pkgs = data.get("package") or []
            by_name = defaultdict(list)
            for p in pkgs:
                by_name[p["name"]].append(p)
            local = {p["name"] for p in pkgs if not p.get("source")}

            def key(p):
                return "%s %s" % (p["name"], p["version"])

            index = {key(p): p for p in pkgs}

            def resolve(dep):
                parts = dep.split()
                if len(parts) >= 2:
                    return index.get("%s %s" % (parts[0], parts[1]))
                cands = by_name.get(parts[0]) or []
                return cands[0] if cands else None

            def priv_of(p):
                src = p.get("source") or ""
                if src.startswith("git+"):
                    return "git dependency"
                if src and "crates.io-index" not in src and "index.crates.io" not in src:
                    return "private registry %s" % host_of(src.split("+", 1)[-1])
                return None

            seen = set()
            roots = []
            for p in pkgs:
                if p["name"] in local:
                    for dep in p.get("dependencies") or []:
                        child = resolve(dep)
                        if child and child.get("source"):
                            sc = (declared.get(child["name"]) or (None, "runtime", None))[1]
                            roots.append((child, sc))
            roots.sort(key=lambda r: SCOPE_RANK.get(r[1], 9))
            for child, sc in roots:
                queue = deque([(child, [], True)])
                while queue:
                    p, chain, is_direct = queue.popleft()
                    k = key(p)
                    if k in seen:
                        continue
                    seen.add(k)
                    self.add_lib(ecosystem="crates.io", name=p["name"], version=p["version"], confidence="exact",
                                 direct=is_direct, scope=sc, manifest=manifest, lockfile=lock_rel, introduced_by=chain,
                                 workspace=ws, private=priv_of(p))
                    for dep in p.get("dependencies") or []:
                        c = resolve(dep)
                        if c and c.get("source") and key(c) not in seen:
                            queue.append((c, chain + [k.replace(" ", "@")], False))
            for p in pkgs:
                if p.get("source") and key(p) not in seen:
                    self.add_lib(ecosystem="crates.io", name=p["name"], version=p["version"], confidence="exact",
                                 direct=False, scope="runtime", manifest=manifest, lockfile=lock_rel, workspace=ws,
                                 private=priv_of(p))
            return
        for name, (spec, scope, priv) in declared.items():
            version, conf, low = C.classify_declared(spec, "crates.io")
            self.add_lib(ecosystem="crates.io", name=name, version=version, confidence=conf, direct=True, scope=scope,
                         manifest=manifest, declared=spec, workspace=ws, private=priv, lowest=low)
        if declared:
            self.gaps.append("%s: no Cargo.lock; declared version requirements only" % manifest)

    # ------------------------------------------------------------------ RubyGems
    def do_ruby(self, d, names):
        if "Gemfile" not in names and "Gemfile.lock" not in names:
            return
        ws = d or "."
        manifest = self.rel(d, "Gemfile") if "Gemfile" in names else None
        groups, declared, private_gems = {}, {}, {}
        if manifest:
            text = self.read(manifest)
            self.note_manifest(manifest, "RubyGems", "manifest")
            self.scan_leads(manifest, text)
            group_stack, source_stack = [], []
            for n, raw in enumerate(text.splitlines(), 1):
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                m = re.match(r"^source\s+['\"]([^'\"]+)['\"](\s+do)?", line)
                if m:
                    h = host_of(m.group(1))
                    if m.group(2):
                        source_stack.append(h)
                        if h and h not in PUBLIC_HOSTS["RubyGems"]:
                            self.add_private_registry("RubyGems", h, "%s:%d" % (manifest, n))
                    elif h and h not in PUBLIC_HOSTS["RubyGems"]:
                        self.add_mirror("RubyGems", h, "%s:%d (global source)" % (manifest, n))
                    continue
                m = re.match(r"^group\s+(.+?)\s+do", line)
                if m:
                    group_stack.append(re.findall(r":(\w+)", m.group(1)))
                    continue
                if re.match(r"^(platforms?|path|git|github)\b.*\bdo\b", line):
                    group_stack.append([])
                    continue
                if line == "end":
                    if group_stack:
                        group_stack.pop()
                    elif source_stack:
                        source_stack.pop()
                    continue
                m = re.match(r"^ruby\s+['\"]([^'\"]+)['\"]", line)
                if m:
                    self.add_runtime("ruby", m.group(1), "exact" if re.match(r"^\d+\.\d+\.\d+$", m.group(1)) else "range", "%s:%d" % (manifest, n))
                    continue
                m = re.match(r"^gem\s+['\"]([^'\"]+)['\"](.*)$", line)
                if m:
                    name, rest = m.group(1), m.group(2)
                    specs = re.findall(r"['\"]([~<>=!\s]*\d[^'\"]*)['\"]", rest)
                    gs = [g for grp in group_stack for g in grp]
                    gm = re.search(r"group[s]?:\s*\[?([^\]\n]+)\]?", rest)
                    if gm:
                        gs += re.findall(r":(\w+)", gm.group(1))
                    scope = "dev" if gs and all(g in ("development", "test", "dev", "ci", "lint") for g in gs) else "runtime"
                    declared[name] = (", ".join(s.strip() for s in specs) or None, scope)
                    if re.search(r"\b(path|git|github):", rest) or (source_stack and source_stack[-1] and source_stack[-1] not in PUBLIC_HOSTS["RubyGems"]):
                        private_gems[name] = "local, git or private-source gem"
        if "Gemfile.lock" in names:
            lock_rel = self.rel(d, "Gemfile.lock")
            self.note_manifest(lock_rel, "RubyGems", "lockfile")
            self.parse_gemfile_lock(lock_rel, manifest, ws, declared, private_gems)
            return
        for name, (spec, scope) in declared.items():
            version, conf, low = C.classify_declared(spec, "RubyGems") if spec else (None, "unknown", None)
            self.add_lib(ecosystem="RubyGems", name=name, version=version, confidence=conf, direct=True, scope=scope,
                         manifest=manifest, declared=spec, workspace=ws, private=private_gems.get(name), lowest=low)
        if declared:
            self.gaps.append("%s: no Gemfile.lock; declared version requirements only" % manifest)

    def parse_gemfile_lock(self, lock_rel, manifest, ws, declared, private_gems):
        text = self.read(lock_rel)
        section, remote = None, None
        specs, deps, gem_remote, direct = {}, defaultdict(list), {}, []
        cur = None
        for raw in text.splitlines():
            if not raw.strip():
                continue
            indent = len(raw) - len(raw.lstrip())
            s = raw.strip()
            if indent == 0:
                section, remote, cur = s, None, None
                continue
            if section in ("GEM", "GIT", "PATH", "PLUGIN SOURCE"):
                if s.startswith("remote:"):
                    remote = s.split(":", 1)[1].strip()
                    continue
                if indent == 4:
                    m = re.match(r"^([^\s(]+)\s+\(([^)]+)\)", s)
                    if m:
                        name, ver = m.group(1), m.group(2)
                        ver = re.sub(r"-(x86|x64|arm|aarch|universal|java|mingw|mswin|darwin|linux)[\w.\-]*$", "", ver)
                        cur = name
                        if name not in specs:
                            specs[name] = ver
                            gem_remote[name] = (section, remote)
                elif indent >= 6 and cur:
                    m = re.match(r"^([^\s(]+)", s)
                    if m:
                        deps[cur].append(m.group(1))
            elif section == "DEPENDENCIES" and indent == 2:
                direct.append(re.match(r"^([^\s(!]+)", s).group(1))
            elif section == "RUBY VERSION":
                m = re.match(r"^ruby\s+(\d+\.\d+\.\d+)", s)
                if m:
                    self.add_runtime("ruby", m.group(1), "exact", "%s (RUBY VERSION)" % lock_rel)

        def priv_of(name):
            sec, rem = gem_remote.get(name, (None, None))
            if sec in ("GIT", "PATH", "PLUGIN SOURCE"):
                return "git or path gem"
            h = host_of(rem)
            if h and h not in PUBLIC_HOSTS["RubyGems"]:
                return "private gem source %s" % h
            return private_gems.get(name)

        seen = set()
        roots = sorted(((n, (declared.get(n) or (None, "runtime"))[1]) for n in direct), key=lambda r: SCOPE_RANK.get(r[1], 9))
        for root_name, scope in roots:
            queue = deque([(root_name, [], True)])
            while queue:
                name, chain, is_direct = queue.popleft()
                if name in seen or name not in specs:
                    continue
                seen.add(name)
                self.add_lib(ecosystem="RubyGems", name=name, version=specs[name], confidence="exact", direct=is_direct,
                             scope=scope, manifest=manifest, lockfile=lock_rel, introduced_by=chain, workspace=ws,
                             private=priv_of(name))
                for child in deps.get(name, []):
                    if child not in seen and child != "bundler":
                        queue.append((child, chain + ["%s@%s" % (name, specs[name])], False))
        for name, ver in specs.items():
            if name not in seen and name != "bundler" and gem_remote.get(name, ("",))[0] != "PATH":
                self.add_lib(ecosystem="RubyGems", name=name, version=ver, confidence="exact", direct=False,
                             scope="runtime", manifest=manifest, lockfile=lock_rel, workspace=ws, private=priv_of(name))

    # ------------------------------------------------------------------ Packagist
    def do_composer(self, d, names):
        if "composer.json" not in names and "composer.lock" not in names:
            return
        ws = d or "."
        manifest = self.rel(d, "composer.json") if "composer.json" in names else None
        req, req_dev, custom_repos = {}, {}, False
        if manifest:
            text = self.read(manifest)
            self.note_manifest(manifest, "Packagist", "manifest")
            self.scan_leads(manifest, text)
            try:
                data = C.load_jsonc(text)
            except ValueError as e:
                self.error(manifest, "invalid JSON (%s)" % e)
                data = {}
            req, req_dev = data.get("require") or {}, data.get("require-dev") or {}
            php = req.get("php")
            platform_php = ((data.get("config") or {}).get("platform") or {}).get("php")
            if platform_php:
                self.add_runtime("php", platform_php, "exact", "%s (config.platform.php)" % manifest)
            elif php:
                self.add_runtime("php", php, "range", "%s (require.php)" % manifest)
            repos = data.get("repositories") or []
            if isinstance(repos, dict):
                if repos.get("packagist.org") is False or repos.get("packagist") is False:
                    self.add_mirror("Packagist", "(packagist.org disabled)", manifest)
                repos = [v for v in repos.values() if isinstance(v, dict)]
            for r in repos:
                if isinstance(r, dict) and r.get("url"):
                    h = host_of(r.get("url")) or r.get("type")
                    if h not in PUBLIC_HOSTS["Packagist"]:
                        custom_repos = True
                        self.add_private_registry("Packagist", h, "%s (repositories, type %s)" % (manifest, r.get("type")))
        if "composer.lock" in names:
            lock_rel = self.rel(d, "composer.lock")
            self.note_manifest(lock_rel, "Packagist", "lockfile")
            data = C.load_jsonc(self.read(lock_rel))
            nodes = {}
            for key, scope in (("packages", "runtime"), ("packages-dev", "dev")):
                for p in data.get(key) or []:
                    nodes[p["name"].lower()] = (p, scope)

            def priv_of(p):
                if p.get("dist", {}).get("type") == "path" or (p.get("source") or {}).get("type") == "path":
                    return "path repository"
                if custom_repos and p.get("notification-url") != "https://packagist.org/downloads/":
                    return "package from a private repository"
                return None

            seen = set()
            roots = [(n.lower(), "runtime") for n in req] + [(n.lower(), "dev") for n in req_dev]
            if not manifest:
                roots = [(k, v[1]) for k, v in nodes.items()]
            for root_name, scope in roots:
                queue = deque([(root_name, [], True)])
                while queue:
                    name, chain, is_direct = queue.popleft()
                    if name in seen or name not in nodes:
                        continue
                    seen.add(name)
                    p, sc = nodes[name]
                    ver = str(p.get("version") or "")
                    exact = bool(re.match(r"^v?\d", ver))
                    ver = re.sub(r"^v(?=\d)", "", ver) if exact else ver
                    lic = " OR ".join(p.get("license") or []) or None
                    self.add_lib(ecosystem="Packagist", name=p["name"], version=ver if exact else None,
                                 confidence="exact" if exact else "unknown", direct=is_direct, scope=scope if is_direct else sc,
                                 manifest=manifest, lockfile=lock_rel, introduced_by=chain, license=lic, workspace=ws,
                                 private=priv_of(p))
                    for child in (p.get("require") or {}):
                        c = child.lower()
                        if c not in seen and "/" in c:
                            queue.append((c, chain + ["%s@%s" % (p["name"], ver)], False))
            for name, (p, sc) in nodes.items():
                if name not in seen:
                    ver = re.sub(r"^v(?=\d)", "", str(p.get("version") or ""))
                    self.add_lib(ecosystem="Packagist", name=p["name"], version=ver or None,
                                 confidence="exact" if re.match(r"^\d", ver) else "unknown", direct=False, scope=sc,
                                 manifest=manifest, lockfile=lock_rel, workspace=ws, private=priv_of(p))
            return
        for table, scope in ((req, "runtime"), (req_dev, "dev")):
            for name, spec in table.items():
                if "/" not in name:
                    continue
                version, conf, low = C.classify_declared(spec, "Packagist")
                self.add_lib(ecosystem="Packagist", name=name, version=version, confidence=conf, direct=True,
                             scope=scope, manifest=manifest, declared=spec, workspace=ws, lowest=low)
        if req or req_dev:
            self.gaps.append("%s: no composer.lock; declared version constraints only" % manifest)

    # ------------------------------------------------------------------ NuGet
    def nuget_sources(self, d):
        """Sources from NuGet.Config files in d and its ancestors: (private_mappings, mirror_host, has_private)."""
        mappings, mirror, nugetorg = [], None, True
        parts = d.split("/") if d else []
        found_any = False
        for i in range(len(parts), -1, -1):
            base = "/".join(parts[:i])
            for f in self.file_names(base):
                if f.lower() != "nuget.config":
                    continue
                rel = self.rel(base, f)
                try:
                    root = parse_xml_file(self.root / rel)
                except Exception as e:
                    self.error(rel, "could not parse (%s)" % e)
                    continue
                found_any = True
                srcs = {}
                ps = root.find("packageSources")
                if ps is not None:
                    for child in ps:
                        if child.tag == "clear":
                            nugetorg = False
                        elif child.tag == "add":
                            srcs[child.get("key")] = host_of(child.get("value"))
                    if any(h in PUBLIC_HOSTS["NuGet"] for h in srcs.values()):
                        nugetorg = True
                creds = root.find("packageSourceCredentials")
                if creds is not None:
                    for src in creds:
                        key = src.tag.replace("_x0020_", " ")
                        host = srcs.get(key) or srcs.get(src.tag) or key
                        for add in src:
                            if (add.get("key") or "").lower() in ("password", "cleartextpassword"):
                                self.add_private_registry("NuGet", host, "%s (packageSources %s)" % (rel, key),
                                                          credential="%s (%s)" % (credential_note(add.get("value") or "", rel),
                                                                                  add.get("key")))
                psm = root.find("packageSourceMapping")
                mapped_private = set()
                if psm is not None:
                    for src in psm.findall("packageSource"):
                        h = srcs.get(src.get("key"))
                        if h and h not in PUBLIC_HOSTS["NuGet"]:
                            mapped_private.add(src.get("key"))
                            for pkg in src.findall("package"):
                                mappings.append((pkg.get("pattern") or "", h))
                for key, h in srcs.items():
                    if h and h not in PUBLIC_HOSTS["NuGet"]:
                        self.add_private_registry("NuGet", h, "%s (packageSources %s)" % (rel, key))
                        if key not in mapped_private and psm is None:
                            mirror = mirror or h
        return mappings, mirror, nugetorg, found_any

    def do_nuget(self, d, names):
        projects = sorted(n for n in names if n.lower().endswith((".csproj", ".vbproj", ".fsproj")))
        ws = d or "."
        if "global.json" in names:
            gj = self.rel(d, "global.json")
            try:
                v = ((C.load_jsonc(self.read(gj)) or {}).get("sdk") or {}).get("version")
                if v:
                    self.add_runtime("dotnet", ".".join(v.split(".")[:2]), "range", "%s (sdk.version)" % gj)
            except ValueError as e:
                self.error(gj, "invalid JSON (%s)" % e)
        if not projects and "packages.config" not in names:
            return
        mappings, mirror, _, _ = self.nuget_sources(d)
        central, central_props = self.nuget_central(d)

        def priv_of(pkg_id):
            for pat, h in mappings:
                if pat == "*" or fnmatch.fnmatch(pkg_id.lower(), pat.lower()):
                    return "NuGet feed %s (packageSourceMapping %s)" % (h, pat)
            return None

        for proj in projects:
            rel = self.rel(d, proj)
            try:
                root = parse_xml_file(self.root / rel)
            except Exception as e:
                self.error(rel, "could not parse (%s)" % e)
                continue
            self.note_manifest(rel, "NuGet", "manifest")
            props = dict(central_props)
            for pg in root.iter("PropertyGroup"):
                for child in pg:
                    if isinstance(child.tag, str) and child.text:
                        props[child.tag] = child.text.strip()
            refs = [(r.get("Include") or r.get("Update"), r.get("Version") or r.findtext("Version") or r.get("VersionOverride"),
                     (r.get("PrivateAssets") or r.findtext("PrivateAssets") or "").lower())
                    for r in root.iter("PackageReference")]
            is_test = (props.get("IsTestProject", "").lower() == "true" or
                       any((x or "").lower() in ("microsoft.net.test.sdk", "xunit", "nunit", "mstest.testframework") for x, _, _ in refs))
            tfms = []
            for key in ("TargetFramework", "TargetFrameworks"):
                if props.get(key):
                    tfms += [t.strip() for t in props[key].split(";") if t.strip()]
            tfv = props.get("TargetFrameworkVersion")
            if tfv:
                tfms.append("net" + tfv.lstrip("vV").replace(".", ""))
            for tfm in tfms:
                self.nuget_runtime(tfm, rel)
            sdk = (root.get("Sdk") or "")
            if sdk.lower() == "microsoft.net.sdk.web":
                ver = None
                for tfm in tfms:
                    m = re.match(r"^net(?:coreapp)?(\d+\.\d+)$", tfm)
                    if m:
                        ver = m.group(1)
                        break
                self.add_lib(ecosystem="NuGet", name="Microsoft.AspNetCore.App", version=ver,
                             confidence="range" if ver else "unknown", direct=True, scope="runtime", manifest=rel,
                             workspace=ws, declared='Sdk="Microsoft.NET.Sdk.Web" (implicit framework reference)',
                             lowest=ver, lookup_note="Shared framework; support follows .NET")
            lock_rel = self.rel(d, "packages.lock.json") if "packages.lock.json" in names else None
            direct_scope, declared = {}, []
            for pkg_id, ver, private_assets in refs:
                if not pkg_id:
                    continue
                if ver is None:
                    ver = central.get(pkg_id.lower())
                if ver and "$(" in ver:
                    ver = re.sub(r"\$\(([^)]+)\)", lambda m: props.get(m.group(1), m.group(0)), ver)
                    if "$(" in ver:
                        ver = None
                scope = "dev" if is_test else ("build" if private_assets == "all" else "runtime")
                direct_scope[pkg_id.lower()] = scope
                declared.append((pkg_id, ver, scope))
            if lock_rel:
                self.parse_nuget_lock(lock_rel, rel, ws, direct_scope, priv_of, mirror, is_test)
                continue
            proj_mirror = mirror
            assets = self.nuget_assets(d, rel, declared) if refs else None
            if assets:
                assets_rel, graph, feed = assets
                if feed and not mappings:
                    # restored from a feed the repository's NuGet.Config doesn't declare (user-level config)
                    self.add_private_registry("NuGet", feed, "%s (restore sources)" % assets_rel)
                    proj_mirror = proj_mirror or feed
                self.note_manifest(assets_rel, "NuGet", "lockfile")
                self.nuget_graph(graph, assets_rel, rel, ws, direct_scope, priv_of, proj_mirror, is_test)
                self.nuget_from_assets.append(rel)
                continue
            for pkg_id, ver, scope in declared:
                version, conf, low = C.classify_declared(ver, "NuGet") if ver else (None, "unknown", None)
                self.add_lib(ecosystem="NuGet", name=pkg_id, version=version, confidence=conf, direct=True, scope=scope,
                             manifest=rel, declared=ver, workspace=ws, private=priv_of(pkg_id), mirror=mirror, lowest=low)
        if "packages.config" in names:
            rel = self.rel(d, "packages.config")
            try:
                root = parse_xml_file(self.root / rel)
            except Exception as e:
                self.error(rel, "could not parse (%s)" % e)
                return
            self.note_manifest(rel, "NuGet", "manifest")
            entries = root.findall("package")
            manifest = self.rel(d, projects[0]) if projects else rel
            for p in entries:
                pid, ver = p.get("id"), p.get("version")
                scope = "dev" if (p.get("developmentDependency") or "").lower() == "true" else "runtime"
                self.add_lib(ecosystem="NuGet", name=pid, version=ver, confidence="exact" if ver else "unknown",
                             direct=True, scope=scope, manifest=rel, workspace=ws, private=priv_of(pid or ""), mirror=mirror)
                tf = p.get("targetFramework")
                if tf and re.match(r"^net4\d+$", tf):
                    self.nuget_runtime(tf, "%s (targetFramework)" % rel, evidence_only=True)
            self.errors.append("%s: packages.config doesn't separate direct from transitive dependencies; all %d entries are recorded as direct" % (rel, len(entries)))

    def nuget_central(self, d):
        central, props = {}, {}
        parts = d.split("/") if d else []
        for i in range(len(parts), -1, -1):
            base = "/".join(parts[:i])
            for fname in ("Directory.Packages.props", "Directory.Build.props"):
                rel = self.rel(base, fname)
                if not self.exists(rel):
                    continue
                try:
                    root = parse_xml_file(self.root / rel)
                except Exception as e:
                    self.error(rel, "could not parse (%s)" % e)
                    continue
                for pg in root.iter("PropertyGroup"):
                    for child in pg:
                        if isinstance(child.tag, str) and child.text and child.tag not in props:
                            props[child.tag] = child.text.strip()
                for pv in root.iter("PackageVersion"):
                    if pv.get("Include") and pv.get("Include").lower() not in central:
                        central[pv.get("Include").lower()] = pv.get("Version")
        return central, props

    def nuget_runtime(self, tfm, evidence, evidence_only=False):
        tfm = tfm.strip().lower()
        m = re.match(r"^net(4\d{1,2})$", tfm) or re.match(r"^v?(4(?:\.\d+)+)$", tfm)
        if m:
            digits = m.group(1).replace(".", "")
            version = ".".join(digits)
            self.add_runtime("dotnetfx", version, "exact", evidence)
            return
        m = re.match(r"^net(\d+\.\d+)(?:-[\w.]+)?$", tfm) or re.match(r"^netcoreapp(\d+\.\d+)$", tfm)
        if m:
            self.add_runtime("dotnet", m.group(1), "exact", evidence)

    def parse_nuget_lock(self, lock_rel, manifest, ws, direct_scope, priv_of, mirror, is_test):
        self.note_manifest(lock_rel, "NuGet", "lockfile")
        data = C.load_jsonc(self.read(lock_rel))
        self.nuget_graph(data.get("dependencies") or {}, lock_rel, manifest, ws, direct_scope, priv_of, mirror, is_test)

    def nuget_assets(self, d, proj_rel, declared):
        """Resolved packages from obj/project.assets.json, which `dotnet restore` wrote on this machine, for
        a project without packages.lock.json. Returns (path, graph, private_feed_host) with the graph in the
        packages.lock.json shape ({tfm: {name: {type, resolved, requested, dependencies}}}), or None when
        the file is missing, unreadable or older than the project file's package references. obj/ is
        outside the project walk, so the file is read directly; only package names and versions are kept."""
        assets_rel = self.rel(d, "obj/project.assets.json")
        path = self.root / assets_rel
        try:
            if not path.is_file() or path.stat().st_size > 64_000_000:
                self.nuget_unresolved.append(proj_rel)
                return None
            data = C.load_jsonc(C.read_text(path))
        except (OSError, ValueError) as e:
            self.error(assets_rel, "could not read (%s)" % e)
            self.nuget_unresolved.append(proj_rel)
            return None
        project = data.get("project") or {}
        restored = defaultdict(set)
        for fw in (project.get("frameworks") or {}).values():
            for name, info in ((fw or {}).get("dependencies") or {}).items():
                if ((info or {}).get("target") or "Package") == "Package":
                    restored[name.lower()].add(str((info or {}).get("version") or ""))
        for pkg_id, ver, _scope in declared:
            ranges = restored.get(pkg_id.lower())
            exact = ver and re.fullmatch(r"\d[\w.\-+]*", ver)
            if ranges is None or (exact and not any(
                    nuget_norm(r.strip("[]() ").split(",")[0]) == nuget_norm(ver) for r in ranges)):
                self.nuget_stale_assets.append(proj_rel)
                return None
        targets = data.get("targets") or {}
        asked = {pkg_id.lower(): ver for pkg_id, ver, _scope in declared if ver}
        graph = {}
        for tk in [k for k in targets if "/" not in k] or list(targets):  # "net8.0/win-x64" repeats "net8.0"
            deps = {}
            for key, info in (targets[tk] or {}).items():
                name, _, ver = key.partition("/")
                info = info or {}
                kind = "Project" if info.get("type") == "project" else ("Direct" if name.lower() in restored else "Transitive")
                deps[name] = {"type": kind, "resolved": ver or None, "dependencies": info.get("dependencies") or {},
                              "requested": (asked.get(name.lower()) or sorted(restored[name.lower()])[0])
                              if kind == "Direct" else None}
            graph[tk] = deps
        feed = None
        for src in ((project.get("restore") or {}).get("sources") or {}):
            h = host_of(src) if re.match(r"^https?://", str(src), re.I) else None
            if h and h not in PUBLIC_HOSTS["NuGet"]:
                feed = feed or h
        return assets_rel, graph, feed

    def nuget_graph(self, dependencies, lock_rel, manifest, ws, direct_scope, priv_of, mirror, is_test):
        """Libraries from a resolved NuGet graph: packages.lock.json's `dependencies`, or the same shape
        built from obj/project.assets.json."""
        for tfm, deps in dependencies.items():
            graph = {k.lower(): (k, v) for k, v in (deps or {}).items()}
            seen = set()
            roots = [k for k, (_, v) in graph.items() if (v or {}).get("type") in ("Direct",)]
            for r in roots:
                queue = deque([(r, [], True)])
                scope = direct_scope.get(r, "dev" if is_test else "runtime")
                while queue:
                    key, chain, is_direct = queue.popleft()
                    if key in seen or key not in graph:
                        continue
                    seen.add(key)
                    name, info = graph[key]
                    if (info or {}).get("type") == "Project":
                        continue
                    ver = (info or {}).get("resolved")
                    self.add_lib(ecosystem="NuGet", name=name, version=ver, confidence="exact" if ver else "unknown",
                                 direct=is_direct, scope=scope, manifest=manifest, lockfile=lock_rel, introduced_by=chain,
                                 declared=(info or {}).get("requested") if is_direct else None, workspace=ws,
                                 private=priv_of(name), mirror=mirror)
                    for child in ((info or {}).get("dependencies") or {}):
                        if child.lower() not in seen:
                            queue.append((child.lower(), chain + ["%s@%s" % (name, ver)], False))
            for key, (name, info) in graph.items():
                if key not in seen and (info or {}).get("type") not in ("Project",):
                    ver = (info or {}).get("resolved")
                    self.add_lib(ecosystem="NuGet", name=name, version=ver, confidence="exact" if ver else "unknown",
                                 direct=False, scope="dev" if is_test else "runtime", manifest=manifest, lockfile=lock_rel,
                                 workspace=ws, private=priv_of(name), mirror=mirror)

    # ------------------------------------------------------------------ Pub
    def do_pub(self, d, names):
        if "pubspec.yaml" not in names:
            return
        ws = d or "."
        manifest = self.rel(d, "pubspec.yaml")
        self.note_manifest(manifest, "Pub", "manifest")
        try:
            spec = C.load_yaml(self.read(manifest)) or {}
        except C.YamlError as e:
            self.error(manifest, e)
            spec = {}
        env = spec.get("environment") or {}
        if env.get("sdk"):
            pass  # Dart has no endoflife.date product; the SDK constraint is kept in the manifest only
        declared = {}
        for key, scope in (("dependencies", "runtime"), ("dev_dependencies", "dev")):
            for name, val in (spec.get(key) or {}).items():
                priv, version_spec = None, val if isinstance(val, str) else None
                if isinstance(val, dict):
                    if val.get("sdk"):
                        priv = "SDK dependency (not published on pub.dev)"
                    elif val.get("path") or val.get("git"):
                        priv = "local or git dependency"
                    elif isinstance(val.get("hosted"), (str, dict)):
                        h = host_of(val["hosted"] if isinstance(val["hosted"], str) else val["hosted"].get("url"))
                        if h and h not in PUBLIC_HOSTS["Pub"]:
                            priv = "private pub server %s" % h
                    version_spec = val.get("version")
                declared[name] = (version_spec, scope, priv)
        if "pubspec.lock" in names:
            lock_rel = self.rel(d, "pubspec.lock")
            self.note_manifest(lock_rel, "Pub", "lockfile")
            try:
                lock = C.load_yaml(self.read(lock_rel)) or {}
            except C.YamlError as e:
                self.error(lock_rel, e)
                lock = {}
            flutter_constraint = (lock.get("sdks") or {}).get("flutter")
            for name, info in (lock.get("packages") or {}).items():
                info = info or {}
                dep = str(info.get("dependency") or "")
                src = info.get("source")
                version = str(info.get("version")) if info.get("version") is not None else None
                priv = None
                conf = "exact"
                if src == "sdk":
                    priv = "SDK dependency (not published on pub.dev)"
                    if name == "flutter" and flutter_constraint:
                        version, conf = str(flutter_constraint), "range"
                elif src in ("path", "git"):
                    priv = "local or git dependency"
                elif src == "hosted":
                    desc = info.get("description") or {}
                    h = host_of(desc.get("url") if isinstance(desc, dict) else None)
                    if h and h not in PUBLIC_HOSTS["Pub"]:
                        priv = "private pub server %s" % h
                scope = "dev" if "dev" in dep else (declared.get(name, (None, "runtime"))[1])
                self.add_lib(ecosystem="Pub", name=name, version=version, confidence=conf if version else "unknown",
                             direct=dep.startswith("direct"), scope=scope, manifest=manifest, lockfile=lock_rel,
                             workspace=ws, private=priv, lowest=C.lowest_in_range(version) if conf == "range" and version else None)
            return
        for name, (vs, scope, priv) in declared.items():
            version, conf, low = C.classify_declared(vs, "Pub") if vs else (None, "unknown", None)
            self.add_lib(ecosystem="Pub", name=name, version=version, confidence=conf, direct=True, scope=scope,
                         manifest=manifest, declared=vs, workspace=ws, private=priv, lowest=low)
        if declared:
            self.gaps.append("%s: no pubspec.lock; declared version constraints only" % manifest)

    # ------------------------------------------------------------------ CocoaPods, SwiftPM
    def do_cocoapods(self, d, names):
        if "Podfile" not in names and "Podfile.lock" not in names:
            return
        ws = d or "."
        manifest = self.rel(d, "Podfile") if "Podfile" in names else None
        test_pods = set()
        if manifest:
            text = self.read(manifest)
            self.note_manifest(manifest, "CocoaPods", "manifest")
            in_test = 0
            for line in text.splitlines():
                s = line.split("#", 1)[0].strip()
                if re.match(r"^target\s+['\"][^'\"]*(Tests|UITests|Spec)['\"]", s):
                    in_test += 1
                elif in_test and s == "end":
                    in_test -= 1
                m = re.match(r"^pod\s+['\"]([^'\"/]+)", s)
                if m and in_test:
                    test_pods.add(m.group(1))
                m = re.match(r"^source\s+['\"]([^'\"]+)['\"]", s)
                if m and "cdn.cocoapods.org" not in m.group(1) and "github.com/CocoaPods/Specs" not in m.group(1):
                    self.add_private_registry("CocoaPods", host_of(m.group(1)) or m.group(1), manifest)
        if "Podfile.lock" in names:
            lock_rel = self.rel(d, "Podfile.lock")
            self.note_manifest(lock_rel, "CocoaPods", "lockfile")
            data = C.load_yaml(self.read(lock_rel)) or {}
            direct = {re.match(r"^([^\s/(]+)", str(x)).group(1) for x in (data.get("DEPENDENCIES") or [])}
            private = set()
            for repo, pods in (data.get("SPEC REPOS") or {}).items():
                if repo != "trunk" and "github.com/CocoaPods/Specs" not in str(repo):
                    private |= {str(p).split("/")[0] for p in pods or []}
            private |= {str(k).split("/")[0] for k in (data.get("EXTERNAL SOURCES") or {})}
            seen = set()
            for item in data.get("PODS") or []:
                label = next(iter(item)) if isinstance(item, dict) else str(item)
                m = re.match(r"^([^\s(]+)\s+\(([^)]+)\)", label)
                if not m:
                    continue
                base = m.group(1).split("/")[0]
                if base in seen:
                    continue
                seen.add(base)
                self.add_lib(ecosystem="CocoaPods", name=base, version=m.group(2), confidence="exact",
                             direct=base in direct, scope="dev" if base in test_pods else "runtime", manifest=manifest,
                             lockfile=lock_rel, workspace=ws,
                             private="private spec repo or local pod" if base in private else None)
            if not getattr(self, "_cocoapods_gap", False):
                self._cocoapods_gap = True
                self.gaps.append("CocoaPods: packages are inventoried and support-checked, but OSV.dev has no CocoaPods advisories, so they are not checked for vulnerabilities")

    def do_swift(self, d, names):
        if "Package.swift" not in names and "Package.resolved" not in names:
            return
        ws = d or "."
        manifest = self.rel(d, "Package.swift") if "Package.swift" in names else None
        declared = {}
        if manifest:
            text = self.read(manifest)
            self.note_manifest(manifest, "SwiftURL", "manifest")
            for m in re.finditer(r"\.package\(\s*(?:name:\s*\"[^\"]+\",\s*)?url:\s*\"([^\"]+)\"\s*,\s*([^)]*)\)", text):
                ident = re.sub(r"^https?://|\.git$", "", m.group(1)).rstrip("/")
                args = m.group(2)
                mm = re.search(r"exact:\s*\"([^\"]+)\"|\.exact\(\s*\"([^\"]+)\"", args)
                if mm:
                    declared[ident.lower()] = (ident, mm.group(1) or mm.group(2), "exact")
                    continue
                mm = re.search(r"(?:from:|upToNextMajor\(from:|upToNextMinor\(from:)\s*\"([^\"]+)\"|\"([\d.]+)\"\s*\.\.[.<]", args)
                declared[ident.lower()] = (ident, (mm.group(1) or mm.group(2)) if mm else None, "range" if mm else "unknown")
        if "Package.resolved" in names:
            lock_rel = self.rel(d, "Package.resolved")
            self.note_manifest(lock_rel, "SwiftURL", "lockfile")
            data = C.load_jsonc(self.read(lock_rel))
            pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
            for pin in pins:
                url = pin.get("location") or pin.get("repositoryURL") or ""
                ident = re.sub(r"^https?://|\.git$", "", url).rstrip("/")
                if url.startswith("git@"):
                    ident = re.sub(r"^git@([^:]+):", r"\1/", url).removesuffix(".git")
                ver = (pin.get("state") or {}).get("version")
                h = ident.split("/", 1)[0].lower()
                priv = None if h in ("github.com", "gitlab.com", "bitbucket.org") else "package hosted on %s" % h
                self.add_lib(ecosystem="SwiftURL", name=ident, version=ver, confidence="exact" if ver else "unknown",
                             direct=ident.lower() in declared or not declared, scope="runtime", manifest=manifest,
                             lockfile=lock_rel, workspace=ws, private=priv)
            return
        for _, (ident, ver, conf) in declared.items():
            self.add_lib(ecosystem="SwiftURL", name=ident, version=ver, confidence=conf, direct=True, scope="runtime",
                         manifest=manifest, workspace=ws, lowest=ver if conf == "range" else None)

    # ------------------------------------------------------------------ containers and runtime files
    def image_runtime(self, image_ref, evidence):
        ref = image_ref.strip().strip("'\"")
        if not ref or ref.startswith("$") or ref.lower() == "scratch":
            return False
        digest = None
        if "@sha256:" in ref:
            ref, digest = ref.split("@", 1)
        name, tag = ref, None
        if ":" in ref.rsplit("/", 1)[-1]:
            name, tag = ref.rsplit(":", 1)
        lname = name.lower()
        for prefix in ("docker.io/library/", "docker.io/", "index.docker.io/library/", "library/"):
            if lname.startswith(prefix):
                lname = lname[len(prefix):]
        hit = self.image_map.get(lname)
        if not hit:
            return False
        rid, product = hit
        ev = evidence + (" (digest pinned)" if digest else "")
        version = None
        if tag and tag.lower() not in ("latest", "lts", "current", "stable", "slim", "alpine"):
            m = re.match(r"^v?(\d+(?:\.\d+){0,2})", tag)
            version = m.group(1) if m else None
            if rid == "dotnetfx":
                m = re.match(r"^(\d\.\d(?:\.\d)?)", tag)
                version = m.group(1) if m else None
        conf = "exact" if version and version.count(".") >= 2 else ("range" if version else "unknown")
        if rid in ("debian", "ubuntu") and tag and not re.match(r"^\d", tag):
            rule = next(r for r in self.support_rules["runtimes"] if r["id"] == rid)
            version = (rule.get("codenames") or {}).get(tag.split("-")[0].lower())
            conf = "range" if version else "unknown"
        self.add_runtime(rid, version, conf, ev, product=product)
        if tag:
            m = re.search(r"alpine(\d+\.\d+)", tag)
            if m:
                self.add_runtime("alpine-linux", m.group(1), "range", ev)
            for rid2 in ("debian", "ubuntu"):
                rule = next(r for r in self.support_rules["runtimes"] if r["id"] == rid2)
                for code, ver in (rule.get("codenames") or {}).items():
                    if re.search(r"(^|[-_.])%s($|[-_.])" % code, tag.lower()):
                        self.add_runtime(rid2, ver, "range", ev)
        return True

    def do_docker(self, d, names):
        for n in sorted(names):
            if n == "Dockerfile" or n.endswith(".Dockerfile") or n.startswith("Dockerfile.") or n.lower().endswith(".dockerfile"):
                rel = self.rel(d, n)
                text = self.read(rel, limit=500_000)
                self.note_manifest(rel, "Containers", "manifest")
                self.scan_leads(rel, text)
                args = {}
                stages = []
                for ln, raw in enumerate(text.splitlines(), 1):
                    s = raw.strip()
                    m = re.match(r"^ARG\s+(\w+)\s*=\s*\"?([^\"\s]+)\"?", s, re.I)
                    if m:
                        args.setdefault(m.group(1), m.group(2))
                        continue
                    m = re.match(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", s, re.I)
                    if m:
                        img = re.sub(r"\$\{?(\w+)(?::-([^}]*))?\}?", lambda mm: args.get(mm.group(1), mm.group(2) or ""), m.group(1))
                        stages.append((ln, img, (m.group(2) or "").lower()))
                stage_names = {s[2] for s in stages if s[2]}
                for i, (ln, img, alias) in enumerate(stages):
                    if img.lower() in stage_names:
                        continue
                    role = "final stage" if i == len(stages) - 1 else "build stage"
                    ev = "%s:%d" % (rel, ln) + ("" if len(stages) == 1 else " (%s)" % role)
                    self.image_runtime(img, ev)
            elif re.match(r"^(docker-)?compose[\w.\-]*\.ya?ml$", n, re.I):
                rel = self.rel(d, n)
                text = self.read(rel, limit=500_000)
                self.note_manifest(rel, "Containers", "manifest")
                for ln, raw in enumerate(text.splitlines(), 1):
                    m = re.match(r"^\s*image:\s*['\"]?([^'\"\s#]+)", raw)
                    if m and not self.image_runtime(m.group(1), "%s:%d" % (rel, ln)):
                        if len(self.service_images) < 20:
                            self.service_images.append(m.group(1))

    def do_runtime_files(self, d, names):
        simple = {".nvmrc": "nodejs", ".node-version": "nodejs", ".python-version": "python", ".ruby-version": "ruby",
                  ".java-version": "java", ".go-version": "go", ".php-version": "php"}
        for fname, rid in simple.items():
            if fname in names:
                rel = self.rel(d, fname)
                v = self.read(rel, limit=200).strip().splitlines()[0].strip() if self.read(rel, limit=200).strip() else ""
                v = re.sub(r"^(v|node-|ruby-|python-|go)", "", v)
                if rid == "java":
                    v = re.sub(r"^[a-z]+-", "", v)
                if re.match(r"^\d", v):
                    self.add_runtime(rid, v, "exact" if v.count(".") >= 2 else "range", rel)
        if "runtime.txt" in names:
            rel = self.rel(d, "runtime.txt")
            m = re.match(r"^python-(\d+\.\d+(?:\.\d+)?)", self.read(rel, limit=200).strip())
            if m:
                self.add_runtime("python", m.group(1), "exact", rel)
        if ".tool-versions" in names:
            rel = self.rel(d, ".tool-versions")
            amap = {"nodejs": "nodejs", "node": "nodejs", "python": "python", "ruby": "ruby", "golang": "go", "go": "go",
                    "java": "java", "php": "php", "rust": "rust", "dotnet-core": "dotnet", "dotnet": "dotnet", "deno": "deno", "bun": "bun"}
            for line in self.read(rel).splitlines():
                parts = line.split("#", 1)[0].split()
                if len(parts) >= 2 and parts[0] in amap:
                    v = re.sub(r"^[a-z]+-", "", parts[1])
                    if re.match(r"^\d", v):
                        if amap[parts[0]] == "dotnet":
                            v = ".".join(v.split(".")[:2])
                        self.add_runtime(amap[parts[0]], v, "exact" if v.count(".") >= 2 else "range", "%s (%s)" % (rel, parts[0]))
        if ".sdkmanrc" in names:
            rel = self.rel(d, ".sdkmanrc")
            m = re.search(r"(?m)^java=(\d+(?:\.\d+)*)", self.read(rel))
            if m:
                self.add_runtime("java", m.group(1), "exact", rel)
        for fname in ("rust-toolchain", "rust-toolchain.toml"):
            if fname in names:
                rel = self.rel(d, fname)
                m = re.search(r"(\d+\.\d+(?:\.\d+)?)", self.read(rel, limit=2000))
                if m:
                    self.add_runtime("rust", m.group(1), "exact" if m.group(1).count(".") >= 2 else "range", rel)

    def do_ci(self, d, names):
        targets = []
        if d == "" and ".gitlab-ci.yml" in names:
            targets.append(".gitlab-ci.yml")
        if d == ".github/workflows":
            targets += [self.rel(d, n) for n in names if n.endswith((".yml", ".yaml"))]
        if d == ".circleci" and "config.yml" in names:
            targets.append(".circleci/config.yml")
        setup = {"node-version": "nodejs", "python-version": "python", "java-version": "java", "go-version": "go",
                 "ruby-version": "ruby", "php-version": "php", "dotnet-version": "dotnet"}
        for rel in targets:
            text = self.read(rel, limit=500_000)
            for ln, raw in enumerate(text.splitlines(), 1):
                m = re.match(r"^\s*(?:-\s*)?(?:image|container|name):\s*['\"]?([\w./\-]+:[\w.\-]+)['\"]?\s*$", raw)
                if m and re.match(r"^\s*(?:-\s*)?(image|container)", raw) or (m and "image" in raw):
                    self.image_runtime(m.group(1), "%s:%d" % (rel, ln))
                    continue
                m = re.match(r"^\s*(node-version|python-version|java-version|go-version|ruby-version|php-version|dotnet-version):\s*(.+)$", raw)
                if m:
                    vals = re.findall(r"['\"]?(\d+(?:\.[\dx]+)*)['\"]?", m.group(2))
                    for v in vals[:4]:
                        v = v.replace(".x", "")
                        rid = setup[m.group(1)]
                        if rid == "dotnet":
                            v = ".".join(v.split(".")[:2])
                        self.add_runtime(rid, v, "exact" if v.count(".") >= 2 else "range", "%s:%d" % (rel, ln))

    def do_misc(self, d, names):
        for n in names:
            if n in UNSUPPORTED_MARKERS:
                self.unsupported[UNSUPPORTED_MARKERS[n]].append(self.rel(d, n))
            if n == "osv-scanner.toml":
                rel = self.rel(d, n)
                text = self.read(rel)
                self.scan_leads(rel, text)
                ignores = []
                try:
                    data = tomllib.loads(text)
                    for item in data.get("IgnoredVulns") or []:
                        ignores.append({"id": item.get("id"), "reason": C.redact_text(str(item.get("reason") or ""))[:500],
                                        "ignoreUntil": str(item.get("ignoreUntil")) if item.get("ignoreUntil") else None})
                    for item in data.get("PackageOverrides") or []:
                        if item.get("ignore") or (item.get("vulnerability") or {}).get("ignore"):
                            ignores.append({"package": item.get("name"), "ecosystem": item.get("ecosystem"),
                                            "reason": C.redact_text(str(item.get("reason") or ""))[:500], "ignoreUntil": None})
                except tomllib.TOMLDecodeError as e:
                    self.error(rel, "invalid TOML (%s)" % e)
                self.osv_configs.append({"path": rel, "ignored": ignores})

    # ------------------------------------------------------------------ vendored JS/CSS
    def do_vendored(self):
        found = {}
        html_budget, head_budget = 5000, 20000
        metadata = {}   # vendored library folder -> (priority, package, version, file)
        folders = defaultdict(set)   # vendored-library directory -> its library folders that hold JS/CSS
        for rel, vendor_root in self.all_files:
            name = rel.rsplit("/", 1)[-1]
            low = name.lower()
            ext = os.path.splitext(low)[1]
            folder = None
            if vendor_root:
                inner = rel[len(vendor_root) + 1:].split("/")
                if any(seg.lower() in VENDORED_SKIP_DIRS for seg in inner[:-1]):
                    continue
                if len(inner) > 1:
                    folder = "%s/%s" % (vendor_root, inner[0])
                if folder and len(inner) == 2 and name in VENDORED_METADATA:
                    prio = VENDORED_METADATA.index(name)
                    if folder not in metadata or prio < metadata[folder][0]:
                        try:
                            meta = C.load_jsonc(self.read(rel, limit=200_000))
                        except (OSError, ValueError):
                            meta = None
                        if isinstance(meta, dict) and not meta.get("private") and isinstance(meta.get("name"), str) \
                                and re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[-+][\w.\-+]+)?", str(meta.get("version") or "")):
                            metadata[folder] = (prio, meta["name"].strip().lower(), str(meta["version"]), rel)
                    continue
            if ext in (".js", ".css"):
                if folder:
                    folders[vendor_root].add(folder)
                m = VENDORED_NAME.match(name)
                lib, ver = None, None
                if m:
                    lib, ver = m.group("lib").lower(), m.group("ver")
                if (lib and not ver or (not lib and (".min." in low or vendor_root))) and head_budget > 0:
                    head_budget -= 1
                    try:
                        head = self.read(rel, limit=3000)
                    except OSError:
                        head = ""
                    hm = vendored_header(head)
                    if hm:
                        hl = hm[0]
                        if lib is None or hl.startswith(lib.split("-")[0]) or VENDOR_NPM_NAME.get(hl, hl) == VENDOR_NPM_NAME.get(lib, lib):
                            lib, ver = hl, hm[1]
                if lib and ver:
                    pkg = VENDOR_NPM_NAME.get(lib, lib)
                    if pkg == "font-awesome" and int(ver.split(".")[0]) >= 5:
                        pkg = "@fortawesome/fontawesome-free"
                    found.setdefault((pkg, ver), []).append(rel)
            elif vendor_root:
                continue  # a library's own demo pages say nothing about what the application loads
            elif ext in HTML_EXT and html_budget > 0:
                html_budget -= 1
                try:
                    text = self.read(rel, limit=300_000)
                except OSError:
                    continue
                if "<script" not in text and "<link" not in text:
                    continue
                for tag in re.finditer(r"<(?:script|link)\b[^>]*?(?:src|href)\s*=\s*['\"]([^'\"]+)['\"]", text, re.I):
                    url = tag.group(1)
                    for pat in CDN_PATTERNS:
                        cm = pat.search(url)
                        if cm:
                            pkg = cm.groupdict().get("pkg") or "jquery-ui"
                            if not pkg.startswith("@"):
                                pkg = CDN_NAME_FIX.get(pkg.lower(), pkg.lower())
                            found.setdefault((pkg, cm.group("ver")), []).append(rel)
                            break
        # A folder's package metadata names the library when none of its files did; a file banner wins,
        # because files copied over an older install leave the metadata behind.
        from_metadata = set()
        for folder, (_prio, pkg, ver, rel) in sorted(metadata.items()):
            if not any(p == pkg and any(r.startswith(folder + "/") for r in rels) for (p, _v), rels in found.items()):
                found.setdefault((pkg, ver), []).append(rel)
                from_metadata.add(rel)
        identified = [r for rels in found.values() for r in rels]
        for vendor_root, libs in sorted(folders.items()):
            missing = sorted(f.rsplit("/", 1)[-1] for f in libs if not any(r.startswith(f + "/") for r in identified))
            if missing:
                self.gaps.append("%s: %d of %d vendored library folders have no version this skill can read, so they are "
                                 "not in the inventory and were not checked: %s%s" % (
                                     vendor_root, len(missing), len(libs), ", ".join(missing[:12]),
                                     " and %d more" % (len(missing) - 12) if len(missing) > 12 else ""))
        nuget_owners = defaultdict(list)
        for lib in self.libraries:
            npm_name = NUGET_CONTENT_PACKAGES.get(lib["name"].lower()) if lib["ecosystem"] == "NuGet" else None
            if npm_name and lib.get("version"):
                nuget_owners[(npm_name, lib["version"])].append(lib)
        for (pkg, ver), rels in sorted(found.items(), key=lambda x: x[1][0]):
            rest = []
            for rel in C.dedupe(rels):
                owner = next((lib for lib in nuget_owners.get((pkg, ver), [])
                              if lib["workspace"] in (".", "") or rel.startswith(lib["workspace"] + "/")), None)
                if owner:
                    owner.setdefault("also_installed_as", []).append(rel)
                    self.note_manifest(rel, "NuGet", "content file of %s %s" % (owner["name"], owner["version"]))
                else:
                    rest.append(rel)
            if not rest:
                continue
            # a library split over many files (jquery-ui/ui/*.js, themes) needs a few as evidence, not all
            rest = sorted(rest, key=lambda r: r.count("/"))[:6]
            note = None
            if all(r in from_metadata for r in rest) and not rest[0].endswith("/package.json"):
                note = "Identified from %s; the Bower name is assumed to be the npm name" % rest[0].rsplit("/", 1)[-1]
            entry = self.add_lib(ecosystem="npm", name=pkg, version=ver, confidence="exact", direct=True, scope="runtime",
                                 manifest=rest[0], workspace="(vendored)", vendored=True, lookup_note=note)
            if len(rest) > 1:
                entry["also_installed_as"] = rest[1:]
            for rel in rest:
                self.note_manifest(rel, "npm", "vendored")

    # ------------------------------------------------------------------ privacy and frameworks
    def resolve_gradle(self):
        """Transitive dependencies of the Gradle builds without gradle.lockfile, from published metadata
        (gradle_resolve.py). Skipped offline, with --no-transitive, and whenever a private Maven repository
        or mirror is configured: the names in such a build may be internal (hard rule 5)."""
        if not self.gradle_builds:
            return
        own_gaps = {b["gap"] for b in self.gradle_builds}

        def skip(why):
            self.gaps = [("%s (online resolution skipped: %s)" % (g, why)) if g in own_gaps else g for g in self.gaps]

        if self.opts.offline:
            return skip("offline")
        if self.opts.no_transitive:
            return skip("--no-transitive")
        if self.maven_private:
            return skip("a private Maven repository or mirror is configured, so no names are sent to public repositories")
        import gradle_resolve as GR
        from check_support import Net
        internal = [p.lower() for p in self.opts.internal or []]

        def is_private(ga):
            return any(fnmatch.fnmatch(ga.lower(), p) for p in internal)

        if not C.host_reachable(GR.CENTRAL + "/")[0]:
            return skip("Maven Central unreachable")
        res = GR.Resolver(Net(), is_private=is_private)
        resolved_gaps = {}
        for b in self.gradle_builds:
            entries = [e for e in b["entries"] if not e[0].get("private")]
            platforms = [(key, lib["version"]) for lib, key, _v, is_bom in entries
                         if is_bom and lib["version_confidence"] == "exact"]
            by_scope = {"runtime": [], "dev": []}
            for lib, key, v, is_bom in entries:
                if not is_bom and lib["scope"] in by_scope:
                    by_scope[lib["scope"]].append((key, lib["version"] if lib["version_confidence"] == "exact" else v, False))
            implicit = {ga: v for ga, v in b.get("implicit") or [] if ga not in {k for _l, k, _v, _b in entries}}
            by_scope["runtime"].extend((ga, v, False) for ga, v in implicit.items())
            # the runtime classpath, then the test classpath (which also sees the runtime dependencies)
            align = b.get("align") or []
            graphs = {"runtime": res.resolve(by_scope["runtime"], platforms, align) if by_scope["runtime"] else None,
                      "dev": res.resolve(by_scope["runtime"] + by_scope["dev"], platforms, align) if by_scope["dev"] else None}
            direct = {key: lib for lib, key, _v, _b in entries}
            added, unresolved = 0, {}
            for scope in ("runtime", "dev"):
                g = graphs[scope]
                if not g:
                    continue
                unresolved.update(g["unresolved"])
                for ga, ver in g["selected"].items():
                    if ga in direct:
                        if scope == "runtime" or direct[ga]["scope"] == "dev":
                            self._gradle_set_version(direct[ga], ver)
                        continue
                    if scope == "dev" and graphs["runtime"] and ga in graphs["runtime"]["selected"]:
                        continue
                    path = g["paths"].get(ga) or []
                    if ga in implicit or (path and path[0] in implicit):
                        path = ["org.jetbrains.kotlin:kotlin-gradle-plugin"] + path   # added by the Kotlin plugin
                    self.add_lib(ecosystem="Maven", name=ga, version=ver, confidence="exact", direct=False, scope=scope,
                                 manifest=b["manifest"], introduced_by=path, workspace=b["workspace"],
                                 lookup_note="resolved from published POM/Gradle module metadata, not from a lockfile")
                    added += 1
            gap = ("%s: no gradle.lockfile; %d transitive dependencies resolved from published POM and Gradle module metadata "
                   "on Maven Central and Google Maven (an approximation of Gradle's resolution; annotation processors, lint "
                   "checks and plugins are not expanded; a gradle.lockfile gives exact versions)" % (b["manifest"], added))
            if unresolved:
                items = sorted(unresolved.items())
                gap += "; not resolved: %s%s" % (", ".join("%s (%s)" % kv for kv in items[:8]),
                                                 " and %d more" % (len(items) - 8) if len(items) > 8 else "")
            resolved_gaps[b["gap"]] = gap
        self.gaps = [resolved_gaps.get(g, g) for g in self.gaps]
        self.errors.extend(e for e in res.net.errors if e not in self.errors)

    def _gradle_set_version(self, lib, version):
        """A direct Gradle dependency whose version the resolution settled (a BOM-managed one, a range, or
        one raised by conflict resolution)."""
        if lib.get("version") == version and lib.get("version_confidence") == "exact":
            return
        old_key = (lib.get("manifest") or lib.get("lockfile"), lib["id"])
        before = lib.get("declared")
        lib["version"], lib["version_confidence"], lib["lowest_version"] = version, "exact", None
        lib["id"] = C.make_purl(lib["ecosystem"], lib["name"], version)
        if before and before != version and (before.endswith("+") or before.startswith(("[", "(", "latest."))):
            lib["lookup_note"] = "declared %s; resolves to %s, the newest matching version published (from published metadata)" % (before, version)
        elif before and before != version:
            lib["lookup_note"] = "declared %s; Gradle's conflict resolution selects %s (resolved from published metadata)" % (before, version)
        else:
            lib["lookup_note"] = "version %s set by a platform/BOM (resolved from published metadata)" % version
        if self.lib_index.get(old_key) is lib:
            del self.lib_index[old_key]
        self.lib_index[(old_key[0], lib["id"])] = lib

    def apply_privacy(self):
        internal = [p.lower() for p in self.opts.internal or []]
        mirror_public = bool(self.opts.mirror_public)
        for lib in self.libraries:
            name = lib["name"].lower()
            if any(fnmatch.fnmatch(name, p) for p in internal):
                lib["private"] = "matches internal pattern given for this run"
            elif lib.get("mirror") and not lib.get("private"):
                mk = (lib["ecosystem"], lib["mirror"])
                if mk not in self.mirrors:
                    self.add_mirror(lib["ecosystem"], lib["mirror"], "%s (resolved URLs)" % (lib.get("lockfile") or lib.get("manifest")))
                self.mirrors[mk]["packages"] += 1
                if not mirror_public:
                    lib["private"] = "served by %s, which also serves internal packages (open question 4)" % lib["mirror"]
            elif not lib.get("private") and not lib.get("mirror"):
                for (eco, host), m in self.mirrors.items():
                    if eco == lib["ecosystem"] and eco in ("Maven", "RubyGems", "crates.io", "Packagist") and host:
                        m["packages"] += 1
                        if not mirror_public:
                            lib["private"] = "served by %s, which also serves internal packages (open question 4)" % host
                        break

    def detect_frameworks(self):
        rules = C.load_rules("frameworks") or []
        eco_key = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "go", "crates.io": "cargo",
                   "RubyGems": "gem", "Packagist": "composer", "NuGet": "nuget", "Pub": "pub", "SwiftURL": "swift",
                   "CocoaPods": "cocoapods"}
        # one entry per framework and workspace (spec §9); prefer a direct, runtime-scope, exact match
        best = {}
        for lib in self.libraries:
            key = eco_key.get(lib["ecosystem"])
            if not key:
                continue
            for rule in rules:
                pats = (rule.get("packages") or {}).get(key) or []
                name = lib["name"] if key != "pypi" else C.normalize_pypi(lib["name"])
                if not any(fnmatch.fnmatchcase(name.lower(), str(p).lower()) for p in pats):
                    continue
                if not lib["direct"]:
                    continue
                ident = (rule["framework"], lib["workspace"])
                rank = (SCOPE_RANK.get(lib["scope"], 9), 0 if lib["version_confidence"] == "exact" else 1,
                        0 if not any("*" in str(p) for p in pats) or name.lower() == str(pats[0]).lower() else 1)
                if ident not in best or rank < best[ident][0]:
                    best[ident] = (rank, rule, lib)
        out = []
        for _rank, rule, lib in best.values():
            ws_prefix = "" if lib["workspace"] in (".", "(vendored)") else lib["workspace"] + "/"
            evidence = [x for x in (lib.get("lockfile") or lib.get("manifest"),) if x]
            for sig in rule.get("signals") or []:
                pat = ws_prefix + str(sig)
                hit = next((f for f in self.files if fnmatch.fnmatch(f, pat) and (not ws_prefix or f.startswith(ws_prefix))), None)
                if hit and hit not in evidence:
                    evidence.append(hit)
                if len(evidence) >= 4:
                    break
            out.append({"name": rule["framework"], "category": rule.get("category") or "web-backend",
                        "version": lib["version"], "version_confidence": lib["version_confidence"],
                        "ecosystem": lib["ecosystem"], "package": lib["name"], "library_id": lib["id"],
                        "manifest": lib.get("manifest"), "workspace": lib["workspace"], "evidence": evidence})
        return out

    # ------------------------------------------------------------------ output
    def to_json(self, started):
        langs = sorted(({"name": k, "files": v} for k, v in self.languages.items()), key=lambda x: (-x["files"], x["name"]))
        ecosystems = sorted({m["ecosystem"] for m in self.manifests if m["ecosystem"] != "Containers"})
        for lib in self.libraries:
            if lib.get("private") is None:
                lib["private"] = False
        private_count = sum(1 for lib in self.libraries if lib.get("private"))
        unsupported = [{"ecosystem": k, "files": v[:10]} for k, v in sorted(self.unsupported.items())]
        if self.service_images:
            self.gaps.append("Container images that aren't language runtimes or OS bases were not support-checked: %s" %
                             ", ".join(sorted(set(self.service_images))[:8]))
        if self.plain_requirements:
            names = ", ".join(self.plain_requirements[:6]) + (" and others" if len(self.plain_requirements) > 6 else "")
            self.gaps.append("%s: not a lockfile (no pip-compile annotations), so every listed package is recorded as direct "
                             "and packages it doesn't list (usually transitive dependencies) were not checked" % names)
        def some(paths):
            return ", ".join(paths[:6]) + (" and %d more" % (len(paths) - 6) if len(paths) > 6 else "")
        if self.nuget_from_assets:
            self.gaps.append("NuGet: no packages.lock.json; resolved versions and transitive dependencies of %d project(s) "
                             "come from obj/project.assets.json, the restore output on this machine (not in the repository): %s"
                             % (len(self.nuget_from_assets), some(self.nuget_from_assets)))
        if self.nuget_stale_assets:
            self.gaps.append("NuGet: obj/project.assets.json is older than the package references of %d project(s), so it was "
                             "not used; declared versions only, transitive dependencies not resolved: %s"
                             % (len(self.nuget_stale_assets), some(self.nuget_stale_assets)))
        if self.nuget_unresolved:
            self.gaps.append("NuGet: %d project(s) have no packages.lock.json and no restored obj/project.assets.json; "
                             "declared versions only, transitive dependencies not resolved: %s"
                             % (len(self.nuget_unresolved), some(self.nuget_unresolved)))
        if self.maven_unknown_versions:
            self.gaps.append("Maven: %d dependenc%s with a version managed by a parent POM or BOM outside the repository; "
                             "version unknown unless osv-scanner resolves it" % (
                                 self.maven_unknown_versions, "y" if self.maven_unknown_versions == 1 else "ies"))
        target_name = self.root.name
        return {
            "tool": {"name": "detect_inventory.py", "version": C.TOOL_VERSION},
            "generated_at": C.now_iso(), "started_at": started,
            "target": {"name": target_name, "path": C.posix(self.root), "vcs": C.git_info(self.root)},
            "options": {"offline": bool(self.opts.offline), "no_transitive": bool(self.opts.no_transitive),
                        "internal_patterns": list(self.opts.internal or []),
                        "mirror_policy": ("public-except-internal" if self.opts.mirror_public else "private") if self.mirrors else None},
            "scope": {"files_scanned": len(self.all_files), "excluded_paths": self.excluded,
                      "osv_scanner_configs": [c["path"] for c in self.osv_configs]},
            "languages": langs,
            "ecosystems": ecosystems,
            "manifests": self.manifests,
            "runtimes": sorted(self.runtimes.values(), key=lambda r: r["id"]),
            "frameworks": self.frameworks,
            "libraries": self.libraries,
            "registries": {"private": self.private_registries, "mirrors": list(self.mirrors.values())},
            "private_packages": private_count,
            "go_modules": self.go_modules,
            "maven_private": C.dedupe(self.maven_private),
            "osv_scanner_configs": self.osv_configs,
            "ecosystems_unsupported": unsupported,
            "gaps": C.dedupe(self.gaps),
            "errors": C.dedupe(self.errors),
            "integrity_leads": [dict(lead, id="L-%03d" % (i + 1)) for i, lead in enumerate(self.leads)],
        }


# Files and folders the later steps write under <out>/raw/. A new inventory starts a new run, so these are
# removed first: a scan text or scanner output left from an earlier run must never count as evidence for
# this one (hard rule 2). Nothing else in <out> is touched.
RUN_FILES = ("osv-mcp-scan.txt", "osv-mcp-matches.json", "osv-cli.json", "osv-cli.stderr.txt", "osv-scanner-empty.toml",
             "scanners.json", "scanner-results.json", "support.json", "advisories.json", "findings-draft.json",
             "triage.json", "gopls-vulncheck.txt")
RUN_DIRS = ("osv", "eol", "policies", "scanners", "scan-input")


# Manifests that are code (build scripts and DSL files) are never staged (hard rule 0); the scanners read
# the lockfiles next to them instead.
NOT_STAGED = re.compile(r"(^|/)(build\.gradle(\.kts)?|settings\.gradle(\.kts)?|conanfile\.py|setup\.py|Gemfile|Podfile|"
                        r"Package\.swift|mix\.exs|build\.sbt|project\.clj|rebar\.config|[^/]*\.(py|js|mjs|cjs|ts|html?|rb|kts|gradle))$")


def stage_scan_input(root: Path, raw: Path, paths) -> tuple[str, list[str]]:
    """Copy the manifests and lockfiles, and nothing else, to raw/scan-input/ at their relative paths.
    The osv-scanner CLI and MCP scan are pointed at this folder instead of the project (hard rule 0):
    a scanner that never sees a source file can't send anything derived from one."""
    stage = raw / "scan-input"
    if stage.is_dir() and not stage.is_symlink():
        shutil.rmtree(stage)
    stage.mkdir(parents=True, exist_ok=True)
    root_res = root.resolve()
    staged = []
    for rel in sorted(set(paths)):
        if NOT_STAGED.search(rel) or rel.startswith("/") or ".." in rel.split("/"):
            continue
        src = root / rel
        try:
            if src.is_symlink() or not src.is_file() or not src.resolve().is_relative_to(root_res):
                continue
            dst = stage / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            staged.append(rel)
        except OSError:
            continue
    return C.posix(stage.resolve()), staged


def clear_previous_run(raw: Path) -> list[str]:
    if not (raw / "inventory.json").is_file():
        return []          # not a folder this skill wrote, so leave it alone
    removed = []
    for name in RUN_FILES:
        p = raw / name
        if p.is_file():
            p.unlink()
            removed.append(name)
    for name in RUN_DIRS:
        p = raw / name
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
            removed.append(name + "/")
    return removed


def main(argv=None):
    ap = argparse.ArgumentParser(description="Inventory a project's libraries, frameworks and runtimes.")
    ap.add_argument("path", nargs="?", default=".", help="project root (default: current directory)")
    ap.add_argument("--out", required=True, help="output directory (inventory goes to <out>/raw/inventory.json)")
    ap.add_argument("--offline", action="store_true", help="record that the run is offline")
    ap.add_argument("--no-transitive", action="store_true", help="record that only direct dependencies are reported")
    ap.add_argument("--internal", action="append", default=[], metavar="PATTERN", help="internal package name glob (repeatable)")
    ap.add_argument("--mirror-public", action="store_true", help="packages from a mirror may be looked up publicly unless internal")
    args = ap.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.is_dir():
        print("error: %s is not a directory" % root, file=sys.stderr)
        return 2
    started = C.now_iso()
    removed = clear_previous_run(C.raw_dir(args.out))
    inv = Inventory(root, args)
    inv.run()
    data = inv.to_json(started)
    # only package manifests and lockfiles: not vendored copies, not Dockerfiles, not content files
    data["target"]["scan_path"], data["scope"]["scan_input_files"] = stage_scan_input(
        root, C.raw_dir(args.out),
        [m["path"] for m in data["manifests"] if m["kind"] in ("manifest", "lockfile") and m["ecosystem"] != "Containers"]
        + [f for fs in inv.unsupported.values() for f in fs])
    out = C.raw_dir(args.out) / "inventory.json"
    C.write_json(out, data)
    if removed:
        print("cleared the previous run's files in %s: %s" % (C.raw_dir(args.out), ", ".join(removed)))

    libs = data["libraries"]
    direct = sum(1 for l in libs if l["direct"])
    print("wrote %s" % out)
    print("target: %s (%s)" % (data["target"]["name"], data["target"]["path"]))
    print("files in scope: %d · ecosystems: %s" % (data["scope"]["files_scanned"], ", ".join(data["ecosystems"]) or "none"))
    print("runtimes: %s" % (", ".join("%s %s" % (r["name"], r["version"] or "?") for r in data["runtimes"]) or "none"))
    print("frameworks: %s" % (", ".join("%s %s" % (f["name"], f["version"] or "?") for f in data["frameworks"]) or "none"))
    print("libraries: %d direct, %d transitive · private (no public lookups): %d" % (direct, len(libs) - direct, data["private_packages"]))
    if data["registries"]["mirrors"]:
        print("MIRROR: one registry serves all packages, public and internal (open question 4):")
        for m in data["registries"]["mirrors"]:
            print("  - %s %s (%s; %d packages)" % (m["ecosystem"], m["host"], m["evidence"], m["packages"]))
        if not args.internal and not args.mirror_public:
            print("  All of them are treated as private. Ask the user which names are internal, then rerun with "
                  "--internal PATTERN ... --mirror-public (or leave them private).")
    if data["registries"]["private"]:
        print("private registries: %s" % ", ".join(sorted({"%s %s" % (r["ecosystem"], r["host"]) for r in data["registries"]["private"]})))
    if data["go_modules"]:
        print("Go modules present: %s -> use the osv-scanner CLI without call analysis, not the MCP scan (open question 13)" % ", ".join(data["go_modules"]))
    if data["maven_private"]:
        print("Maven private repository: %s -> neither the MCP scan nor the osv-scanner CLI may run" % "; ".join(data["maven_private"]))
    if data["osv_scanner_configs"]:
        print("osv-scanner.toml files: %s" % ", ".join(c["path"] for c in data["osv_scanner_configs"]))
    if data["integrity_leads"]:
        print("prompt-injection leads to review: %d" % len(data["integrity_leads"]))
    if data["ecosystems_unsupported"]:
        print("unsupported ecosystems: %s" % ", ".join(u["ecosystem"] for u in data["ecosystems_unsupported"]))
    for g in data["gaps"]:
        print("gap: %s" % g)
    for e in data["errors"]:
        print("note: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
