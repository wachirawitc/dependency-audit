"""Transitive dependencies of a Gradle build that has no gradle.lockfile (used by detect_inventory.py).

Gradle itself is never run (hard rule 5). Instead the published metadata of each public artifact is
read over HTTPS from Google's Maven repository and Maven Central: the Gradle module metadata
(`.module`) when the POM says it was published with it, else the POM with its parents, properties,
dependencyManagement and imported BOMs. Conflicts are settled the way Gradle settles them: the highest
requested version wins, a `strictly` version beats the rest, and constraints from platforms (BOMs)
take part once their module is in the graph.

This is an approximation, and the inventory says so: variant attributes are matched by a fixed
preference (Android, then JVM, release, runtime), exclusions apply only when every path excludes a
module, capabilities and component metadata rules are not modelled, and repositories other than the
two above are not asked.

Only public group:artifact:version triples are sent (hard rule 5). The caller does not call this at all
when the build declares a private Maven repository, and skips names marked private.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import re
import threading
import xml.etree.ElementTree as ET
from collections import defaultdict

import common as C

GOOGLE = "https://dl.google.com/android/maven2"
CENTRAL = "https://repo1.maven.org/maven2"
# Groups published on Google's Maven repository (https://maven.google.com/web/index.html).
GOOGLE_GROUPS = ("androidx.", "com.android.", "com.google.android.", "com.google.firebase", "com.google.gms",
                 "com.google.mlkit", "com.google.ar", "com.google.testing.platform", "com.google.devtools.ksp")
MAX_MODULES = 3000      # per run; a guard against runaway graphs
MAX_PARENT_DEPTH = 12
GRADLE_METADATA_MARKER = "published-with-gradle-metadata"


class Unresolved(Exception):
    pass


def ga_split(ga):
    g, _, a = ga.partition(":")
    return g, a


def _xml(text):
    if re.search(r"<!DOCTYPE", text[:4096], re.I):
        raise ValueError("DOCTYPE declarations are not accepted")
    root = ET.fromstring(text.encode("utf-8"))
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _txt(el, path):
    v = el.findtext(path) if el is not None else None
    return v.strip() if v else None


# ---------------------------------------------------------------------- version specs
def _range_parts(spec):
    """Maven range "[1.0,2.0)" -> (lo, lo_inclusive, hi, hi_inclusive); None when not a range."""
    m = re.fullmatch(r"\s*([\[(])\s*([^,\])]*?)\s*(?:,\s*([^\])]*?)\s*)?([\])])\s*", spec or "")
    if not m:
        return None
    lo, hi = m.group(2) or None, m.group(3)
    if m.group(3) is None:          # "[1.0]" is an exact version
        hi = lo
    return lo, m.group(1) == "[", hi or None, m.group(4) == "]"


def in_range(v, spec):
    parts = _range_parts(spec)
    if parts:
        lo, lo_inc, hi, hi_inc = parts
        if lo and (C.compare_versions(v, lo) < 0 or (C.compare_versions(v, lo) == 0 and not lo_inc)):
            return False
        if hi and (C.compare_versions(v, hi) > 0 or (C.compare_versions(v, hi) == 0 and not hi_inc)):
            return False
        return True
    if spec.endswith("+"):          # Gradle prefix version "1.2.+"
        return v.startswith(spec[:-1])
    return False


def is_dynamic(spec):
    return bool(spec) and (_range_parts(spec) is not None or spec.endswith("+") or spec.startswith("latest."))


class Resolver:
    def __init__(self, net, is_private=lambda ga: False, workers=8):
        self.net = net
        self.is_private = is_private
        self.workers = workers
        self.lock = threading.Lock()
        self.meta_cache: dict[tuple, object] = {}
        self.pom_cache: dict[tuple, object] = {}
        self.versions_cache: dict[str, object] = {}
        self.not_found: set[str] = set()
        self.errors: list[str] = []
        self.fetched = 0

    # ------------------------------------------------------------------ fetching
    def hosts(self, g):
        return [GOOGLE, CENTRAL] if g.startswith(GOOGLE_GROUPS) else [CENTRAL, GOOGLE]

    def fetch(self, g, a, path_tail, kind="text"):
        """First repository that has the file, as (text, base) ; None when no repository has it."""
        if self.is_private("%s:%s" % (g, a)):
            raise Unresolved("private")
        base_path = "%s/%s" % (g.replace(".", "/"), a)
        last = None
        for h in self.hosts(g):
            try:
                return self.net.get("%s/%s/%s" % (h, base_path, path_tail), kind=kind, retries=1), h
            except C.FetchError as e:
                if e.status == 404:
                    continue
                last = e
        if last is not None:
            raise Unresolved(last.message)
        return None

    def versions(self, ga):
        with self.lock:
            if ga in self.versions_cache:
                return self.versions_cache[ga]
        g, a = ga_split(ga)
        out = []
        try:
            got = self.fetch(g, a, "maven-metadata.xml")
            if got:
                out = re.findall(r"<version>([^<]+)</version>", got[0])
        except Unresolved:
            pass
        with self.lock:
            self.versions_cache[ga] = out
        return out

    def pick(self, ga, spec):
        """A concrete version for a requested spec (exact versions are returned as they are)."""
        if not spec:
            return None
        if not is_dynamic(spec):
            return spec
        avail = self.versions(ga)
        stable = [v for v in avail if not C.is_prerelease(v)] or avail
        if spec.startswith("latest."):
            ok = stable
        else:
            ok = [v for v in stable if in_range(v, spec)]
        return max(ok, key=C.version_sort_key) if ok else None

    # ------------------------------------------------------------------ POM model
    def pom(self, g, a, v, depth=0):
        """Effective POM: {"g", "v", "props", "dm": {ga: (version, scope, type)}, "deps": [...], "gradle": bool}."""
        key = (g, a, v)
        with self.lock:
            if key in self.pom_cache:
                cached = self.pom_cache[key]
                if isinstance(cached, Exception):
                    raise cached
                return cached
        try:
            result = self._pom(g, a, v, depth)
        except (Unresolved, ValueError, ET.ParseError) as e:
            err = e if isinstance(e, Unresolved) else Unresolved("unreadable POM (%s)" % e)
            with self.lock:
                self.pom_cache[key] = err
            raise err
        with self.lock:
            self.pom_cache[key] = result
        return result

    def _pom(self, g, a, v, depth):
        if depth > MAX_PARENT_DEPTH:
            raise Unresolved("parent POM chain too deep")
        got = self.fetch(g, a, "%s/%s-%s.pom" % (v, a, v))
        if got is None:
            with self.lock:
                self.not_found.add("%s:%s:%s" % (g, a, v))
            raise Unresolved("not found")
        text = got[0]
        with self.lock:
            self.fetched += 1
        root = _xml(text)
        props, dm, deps = {}, {}, []
        parent = root.find("parent")
        pg, pv = _txt(parent, "groupId"), _txt(parent, "version")
        if parent is not None and pg and pv and _txt(parent, "artifactId"):
            pp = self.pom(pg, _txt(parent, "artifactId"), pv, depth + 1)
            props.update(pp["props"])
            dm.update(pp["dm"])
            deps.extend(pp["deps"])
        own_g = _txt(root, "groupId") or pg or g
        own_v = _txt(root, "version") or pv or v
        props.update({"project.groupId": own_g, "pom.groupId": own_g, "groupId": own_g,
                      "project.version": own_v, "pom.version": own_v, "version": own_v,
                      "project.artifactId": a, "artifactId": a,
                      "project.parent.version": pv or "", "parent.version": pv or "",
                      "project.parent.groupId": pg or "", "parent.groupId": pg or ""})
        pe = root.find("properties")
        if pe is not None:
            for el in pe:
                if isinstance(el.tag, str):
                    props[el.tag] = (el.text or "").strip()

        def interp(s):
            for _ in range(6):
                if not s or "${" not in s:
                    break
                s = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), s)
            return s if s and "${" not in s else None

        own_dm = {}
        for dep in root.findall("dependencyManagement/dependencies/dependency"):
            dg, da = interp(_txt(dep, "groupId")), interp(_txt(dep, "artifactId"))
            dv = interp(_txt(dep, "version"))
            scope, typ = (_txt(dep, "scope") or "compile"), (_txt(dep, "type") or "jar")
            if not dg or not da:
                continue
            if scope == "import" and typ == "pom" and dv:
                try:
                    imported = self.pom(dg, da, dv, depth + 1)
                    for k, val in imported["dm"].items():
                        own_dm.setdefault(k, val)
                except Unresolved:
                    pass
                continue
            own_dm["%s:%s" % (dg, da)] = (dv, scope, typ)
        dm.update(own_dm)
        own_deps = []
        for dep in root.findall("dependencies/dependency"):
            dg, da = interp(_txt(dep, "groupId")), interp(_txt(dep, "artifactId"))
            if not dg or not da:
                continue
            ga = "%s:%s" % (dg, da)
            managed = dm.get(ga)
            dv = interp(_txt(dep, "version")) or (managed[0] if managed else None)
            scope = _txt(dep, "scope") or (managed[1] if managed else None) or "compile"
            excl = {"%s:%s" % (interp(_txt(x, "groupId")) or "*", interp(_txt(x, "artifactId")) or "*")
                    for x in dep.findall("exclusions/exclusion")}
            own_deps.append({"ga": ga, "spec": dv, "scope": scope, "optional": (_txt(dep, "optional") or "") == "true",
                             "classifier": _txt(dep, "classifier"), "type": _txt(dep, "type") or "jar", "excludes": excl})
        # a child POM's dependency replaces the parent's entry for the same module
        names = {d["ga"] for d in own_deps}
        deps = [d for d in deps if d["ga"] not in names] + own_deps
        return {"g": own_g, "v": own_v, "props": props, "dm": dm, "deps": deps,
                "gradle": GRADLE_METADATA_MARKER in text}

    # ------------------------------------------------------------------ Gradle module metadata
    @staticmethod
    def _variant_score(attrs, platform):
        cat = attrs.get("org.gradle.category", "library")
        if platform:
            return (1,) if cat in ("platform", "enforced-platform") else None
        if cat != "library" or "org.gradle.docstype" in attrs:
            return None
        usage = attrs.get("org.gradle.usage", "")
        u = {"java-runtime": 3, "java-api": 2, "kotlin-runtime": 1}.get(usage)
        if u is None:
            return None
        ptype = attrs.get("org.jetbrains.kotlin.platform.type")
        p = {None: 2, "androidJvm": 3, "jvm": 2}.get(ptype)
        if p is None:
            return None
        env = {"android": 2, "standard-jvm": 1}.get(attrs.get("org.gradle.jvm.environment"), 1)
        build = attrs.get("com.android.build.api.attributes.BuildTypeAttr")
        b = {"release": 1, None: 0}.get(build, -1)
        return (p, env, u, b)

    def _version_spec(self, ver):
        """(spec, strict) from a .module version object."""
        if not isinstance(ver, dict):
            return None, False
        if ver.get("strictly"):
            return ver["strictly"], True
        return ver.get("requires") or ver.get("prefers"), False

    def module_variant(self, g, a, v, platform=False, hops=0):
        """Dependencies, constraints and platforms of the chosen variant, or None to use the POM."""
        got = self.fetch(g, a, "%s/%s-%s.module" % (v, a, v))
        if got is None:
            return None
        try:
            data = json.loads(got[0])
        except ValueError:
            return None
        best = None
        for var in data.get("variants") or []:
            score = self._variant_score(var.get("attributes") or {}, platform)
            if score is not None and (best is None or score > best[0]):
                best = (score, var)
        if best is None:
            return {"deps": [], "constraints": []}
        var = best[1]
        at = var.get("available-at")
        if at and at.get("group") and at.get("module") and at.get("version") and hops < 3:
            return {"deps": [{"ga": "%s:%s" % (at["group"], at["module"]), "spec": at["version"], "strict": False,
                              "excludes": set(), "platform": False}], "constraints": []}
        deps = []
        for dep in var.get("dependencies") or []:
            if not dep.get("group") or not dep.get("module"):
                continue
            spec, strict = self._version_spec(dep.get("version"))
            cat = (dep.get("attributes") or {}).get("org.gradle.category")
            deps.append({"ga": "%s:%s" % (dep["group"], dep["module"]), "spec": spec, "strict": strict,
                         "excludes": {"%s:%s" % (x.get("group", "*"), x.get("module", "*")) for x in dep.get("excludes") or []},
                         "platform": cat in ("platform", "enforced-platform")})
        cons = []
        for c in var.get("dependencyConstraints") or []:
            if c.get("group") and c.get("module"):
                spec, strict = self._version_spec(c.get("version"))
                if spec:
                    cons.append({"ga": "%s:%s" % (c["group"], c["module"]), "spec": spec, "strict": strict})
        return {"deps": deps, "constraints": cons}

    # ------------------------------------------------------------------ one node
    def meta(self, ga, v, platform=False):
        """{"deps": [edge], "constraints": [constraint]} for one module version (cached)."""
        key = (ga, v, platform)
        with self.lock:
            if key in self.meta_cache:
                cached = self.meta_cache[key]
                if isinstance(cached, Unresolved):
                    raise cached
                return cached
        try:
            result = self._meta(ga, v, platform)
        except Unresolved as e:
            with self.lock:
                self.meta_cache[key] = e
            raise
        with self.lock:
            self.meta_cache[key] = result
        return result

    def _meta(self, ga, v, platform):
        g, a = ga_split(ga)
        pom = self.pom(g, a, v)
        if pom["gradle"]:
            mod = self.module_variant(g, a, v, platform)
            if mod is not None:
                return mod
        if platform:
            # a POM used as a platform: its dependencyManagement becomes constraints
            return {"deps": [], "constraints": [{"ga": k, "spec": val[0], "strict": False}
                                                for k, val in pom["dm"].items() if val[0] and val[2] != "pom"]}
        deps = []
        for d in pom["deps"]:
            if d["optional"] or d["scope"] not in ("compile", "runtime") or d["type"] not in ("jar", "aar", "bundle", None):
                continue
            if d["classifier"] in ("tests", "sources", "javadoc"):
                continue
            deps.append({"ga": d["ga"], "spec": d["spec"], "strict": False, "excludes": d["excludes"], "platform": False})
        return {"deps": deps, "constraints": []}

    # ------------------------------------------------------------------ graph
    def resolve(self, roots, platforms=(), extra_constraints=()):
        """roots: [(ga, spec, strict)]; platforms: [(ga, version)] declared with platform();
        extra_constraints: [(ga, version)] the build adds itself (the Kotlin plugin's stdlib alignment).
        Returns {"selected": {ga: version}, "paths": {ga: [ga, ...]}, "unresolved": {ga: reason}}."""
        unresolved = {}
        constraints = defaultdict(list)        # ga -> [(version, strict)]
        for ga, version in extra_constraints:
            constraints[ga].append((version, False))
        platform_seen = set()

        def add_platform(ga, version):
            if (ga, version) in platform_seen or not version:
                return
            platform_seen.add((ga, version))
            try:
                m = self.meta(ga, version, platform=True)
            except Unresolved as e:
                unresolved[ga] = str(e)
                return
            for c in m["constraints"]:
                cv = self.pick(c["ga"], c["spec"])
                if cv:
                    constraints[c["ga"]].append((cv, c["strict"]))
            for d in m["deps"]:            # a platform can import other platforms
                if d.get("platform") or d["ga"].endswith("-bom"):
                    add_platform(d["ga"], self.pick(d["ga"], d["spec"]))

        for ga, version in platforms:
            add_platform(ga, version)

        requests = defaultdict(list)           # ga -> [(version, strict)] from edges
        excl = {}                              # ga -> set of excludes common to every path so far
        expanded = {}                          # ga -> version expanded
        parent = {}
        for ga, spec, strict in roots:
            requests.setdefault(ga, [])       # a versionless root takes its version from a platform
            v = self.pick(ga, spec)
            if v:
                requests[ga].append((v, strict))
            excl[ga] = set()

        def choose(ga):
            cands = requests.get(ga, []) + (constraints.get(ga, []) if ga in requests else [])
            if not cands:
                return None
            strict = [v for v, s in cands if s]
            pool = strict or [v for v, _ in cands]
            return max(pool, key=C.version_sort_key)

        def excluded(ga, ex):
            g, a = ga_split(ga)
            return any(e in (ga, "%s:*" % g, "*:%s" % a, "*:*") for e in ex)

        frontier = [ga for ga, _s, _t in roots]
        rounds = 0
        while frontier and rounds < 200:
            rounds += 1
            todo = []
            for ga in dict.fromkeys(frontier):
                v = choose(ga)
                if v and expanded.get(ga) != v and ga not in unresolved:
                    todo.append((ga, v))
            if not todo:
                break
            if self.fetched > MAX_MODULES:
                for ga, _v in todo:
                    unresolved.setdefault(ga, "module limit reached")
                break
            with cf.ThreadPoolExecutor(max_workers=self.workers) as pool:
                futs = {pool.submit(self.meta, ga, v): (ga, v) for ga, v in todo}
                results = {}
                for f in cf.as_completed(futs):
                    ga, v = futs[f]
                    try:
                        results[ga] = f.result()
                    except Unresolved as e:
                        unresolved[ga] = str(e)
                    except Exception as e:  # one bad record never stops the inventory
                        unresolved[ga] = "%s: %s" % (type(e).__name__, e)
            frontier = []
            for ga, v in todo:
                expanded[ga] = v
                m = results.get(ga)
                if m is None:
                    continue
                for c in m["constraints"]:
                    cv = self.pick(c["ga"], c["spec"])
                    if cv:
                        constraints[c["ga"]].append((cv, c["strict"]))
                        if c["ga"] in requests:
                            frontier.append(c["ga"])
                for d in m["deps"]:
                    if self.is_private(d["ga"]):
                        continue
                    if d.get("platform"):
                        add_platform(d["ga"], self.pick(d["ga"], d["spec"]))
                        frontier.extend(k for k in list(constraints) if k in requests)
                        continue
                    child_ex = excl.get(ga, set()) | d["excludes"]
                    if excluded(d["ga"], excl.get(ga, set())):
                        continue
                    dv = self.pick(d["ga"], d["spec"])
                    if not dv:
                        # versionless edge: only a constraint or another edge can give it a version
                        requests.setdefault(d["ga"], [])
                        if not constraints.get(d["ga"]):
                            unresolved.setdefault(d["ga"], "no version in the published metadata")
                    else:
                        requests[d["ga"]].append((dv, d["strict"]))
                    old = excl.get(d["ga"])
                    new_ex = child_ex if old is None else (old & child_ex)
                    if old is None or new_ex != old:
                        excl[d["ga"]] = new_ex
                        if old is not None:
                            expanded.pop(d["ga"], None)   # fewer exclusions: expand again
                    parent.setdefault(d["ga"], ga)
                    frontier.append(d["ga"])

        # final pass: keep only what is reachable through the selected versions
        selected, paths = {}, {}
        root_set = [ga for ga, _s, _t in roots]
        queue = list(root_set)
        seen = set(queue)
        via = {ga: [] for ga in root_set}
        while queue:
            ga = queue.pop(0)
            v = choose(ga)
            if not v:
                continue
            selected[ga] = v
            paths[ga] = via[ga]
            m = self.meta_cache.get((ga, v, False))
            if not isinstance(m, dict):
                continue
            for d in m["deps"]:
                if d.get("platform") or d["ga"] in seen or excluded(d["ga"], excl.get(ga, set())) or self.is_private(d["ga"]):
                    continue
                seen.add(d["ga"])
                via[d["ga"]] = via[ga] + [ga]
                queue.append(d["ga"])
        for ga in list(unresolved):
            if ga in selected and unresolved[ga] == "no version in the published metadata":
                del unresolved[ga]
        return {"selected": selected, "paths": paths,
                "unresolved": {k: v for k, v in unresolved.items() if k in seen or k in dict(platforms)}}
