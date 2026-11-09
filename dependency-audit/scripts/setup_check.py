#!/usr/bin/env python3
"""--setup and --setup-dry (spec §2): is this machine, and with a path this project, ready for an audit?

Usage:
    python setup_check.py [path] [--mode dry|setup] [--format json|text] [--timeout SECONDS]

Read-only: it installs nothing, never runs `claude mcp add` or `remove`, and writes no files.

  machine  Python 3.11+ and the skill's own files. The osv-scanner binary: on PATH, in the user-level
           folders --setup installs into, or wherever the MCP registration points; `--version` must
           meet the minimum. The osv-scanner MCP server: `claude mcp get osv-scanner`, run from the
           current directory (whose project and local registrations apply to this session), gives its
           effective scope, command and connection status; Claude Code's config files (~/.claude.json
           or $CLAUDE_CONFIG_DIR/.claude.json, and .mcp.json in the current directory and the target)
           show registrations of the same name at other scopes, and servers registered under another
           name. `claude mcp list` isn't used: it starts every configured server to check its health,
           while `get` starts only this one. gopls and govulncheck are n/a (open question 13). Optional
           scanners are detected only (open question 16).
  network  one plain HTTPS request to each host in hard rule 5 (rules/requirements.yaml), with no
           package names; any HTTP answer counts as reachable. --mode setup also checks the download
           hosts of the install methods the plan uses, and leaves out downloads that can't work.
  project  with a path: detect_inventory.py reads file names and manifests (offline, nothing written) to
           find the ecosystems, so which optional tools apply, and the gaps an audit will hit whatever is
           installed: private registries and mirrors, Maven private repositories, manifests without
           lockfiles, unsupported ecosystems, Go call analysis.

Every item gets a status (ok, missing, outdated, conflict, unreachable, n/a; project gaps aren't
requirements and use "gap"), an impact on an audit (blocks, degrades, none) and a fix: the commands
--setup would run, or "manual" for what setup never changes (Python itself, conflicts, project gaps,
optional scanners). "plan" lists the --setup commands in order; none of them runs until the user
approves the plan (spec §2 Setup step 2).

Verdict and exit code: ready 0, ready-with-gaps 1 (something degrades), not-ready 2 (something blocks).
JSON on stdout by default, or a text table with --format text. Standard library only.
"""
import sys

if sys.version_info < (3, 11):
    # common.py needs 3.11, so report this one item and stop. This file parses on older Pythons too.
    import json as _json
    _found = "%d.%d.%d" % tuple(sys.version_info[:3])
    print(_json.dumps({
        "tool": {"name": "setup_check.py"},
        "items": [{"id": "python", "group": "machine", "name": "Python 3.11 or later", "status": "outdated",
                   "impact": "blocks", "found": "%s (%s)" % (_found, sys.executable),
                   "detail": "The skill's scripts need Python 3.11 or later. The other checks need it too, so they didn't run.",
                   "fix": {"by": "manual", "hint": "Install Python 3.11 or later, then run this check again with it."}}],
        "plan": [], "verdict": "not-ready", "verdict_text": "Not ready", "exit_code": 2, "suggest_setup": False}, indent=2))
    sys.exit(2)

import argparse
import concurrent.futures as cf
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

TOOL = {"name": "setup_check.py", "version": C.TOOL_VERSION}
IMPACT_RANK = {"none": 0, "degrades": 1, "blocks": 2}
VERDICTS = {0: ("ready", "Ready"), 1: ("ready-with-gaps", "Ready with gaps"), 2: ("not-ready", "Not ready")}
OPTIONAL_HINT = "Optional, and setup only reports it (open question 16). Install it yourself if you want this extra check."


# --------------------------------------------------------------------------- small helpers

def current_os():
    return {"windows": "windows", "darwin": "darwin", "linux": "linux"}.get(platform.system().lower(), platform.system().lower())


def current_arch():
    machine = platform.machine().lower()
    if os.name == "nt":
        machine = (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or machine).lower()
    return {"x86_64": "amd64", "amd64": "amd64", "x64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)


def exe_suffix():
    return ".exe" if os.name == "nt" else ""


def fill(template, **values):
    return re.sub(r"\{(\w+)\}", lambda m: str(values.get(m.group(1), m.group(0))), template)


def same_file(a, b):
    if not a or not b:
        return False
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def display_command(argv):
    """A command line to show the user. The program is shortened to its name when that name finds the same
    file on PATH, so the line reads the same in any shell; argv stays exact."""
    first = argv[0]
    short = os.path.basename(first)
    stem = os.path.splitext(short)[0] if os.name == "nt" else short
    if os.path.isabs(first) and same_file(shutil.which(stem), first):
        first = stem
    parts = [first] + [str(a) for a in argv[1:]]
    return subprocess.list2cmdline(parts) if os.name == "nt" else shlex.join(parts)


def item(id_, group, name, status, impact="none", found=None, detail=None, fix=None, **extra):
    d = {"id": id_, "group": group, "name": name, "status": status, "impact": impact, "found": found,
         "detail": detail, "fix": fix}
    d.update(extra)
    return d


def manual(hint):
    return {"by": "manual", "hint": hint}


def sentences(*parts):
    """Join text fragments into sentences, adding the full stop a fragment lacks."""
    out = []
    for p in parts:
        p = (p or "").strip()
        if p:
            out.append(p if p.endswith((".", "!", "?", ")")) else p + ".")
    return " ".join(out)


def add_detail(it, text):
    it["detail"] = sentences(it.get("detail"), text)


def run_text(argv, cwd=None, timeout=120):
    try:
        r = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, "timed out after %d s" % timeout
    except OSError as e:
        return None, str(e)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def git_root(path):
    if not shutil.which("git"):
        return None
    code, out = run_text(["git", "-c", "core.fsmonitor=false", "-C", str(path), "rev-parse", "--show-toplevel"], timeout=20)
    return Path(out.strip()) if code == 0 and out.strip() else None


def norm_key(path_text):
    s = str(path_text).replace("\\", "/").rstrip("/")
    return s.lower() if os.name == "nt" else s


# --------------------------------------------------------------------------- machine: Python and skill files

def check_python(req):
    py = req.get("python") or {}
    minimum = str(py.get("min_version") or "3.11")
    found = "%s (%s)" % (platform.python_version(), sys.executable)
    if C.compare_versions(platform.python_version(), minimum) >= 0:
        return item("python", "machine", "Python %s or later" % minimum, "ok", found=found, detail=py.get("needed_for"))
    hint = (py.get("hint") or {}).get(current_os()) or "Install Python %s or later." % minimum
    return item("python", "machine", "Python %s or later" % minimum, "outdated", "blocks", found=found,
                detail=py.get("needed_for"), fix=manual(hint))


def check_skill_files(req):
    problems = []
    for rel in req.get("skill_files") or []:
        p = C.SKILL_DIR / rel
        if not p.is_file():
            problems.append("%s is missing" % rel)
            continue
        try:
            text = p.read_text(encoding="utf-8")
            if rel.endswith(".json"):
                json.loads(text)
            elif rel.endswith(".yaml"):
                C.load_yaml(text)
            elif rel.endswith(".py"):
                compile(text, str(p), "exec")
        except (OSError, ValueError, SyntaxError) as e:
            problems.append("%s can't be read: %s" % (rel, e))
    name = "Skill files (scripts, schema, template, rules)"
    if problems:
        return item("skill-files", "machine", name, "missing", "blocks", detail="; ".join(problems),
                    fix=manual("Reinstall the dependency-audit skill so every file in its package is present."))
    return item("skill-files", "machine", name, "ok", found=str(C.SKILL_DIR),
                detail="%d files present and readable" % len(req.get("skill_files") or []))


# --------------------------------------------------------------------------- machine: binaries

def binary_candidates(name, extra=()):
    seen, out = set(), []
    paths = [shutil.which(name)] + [str(d / (name + exe_suffix())) for d in C.user_bin_dirs(name)] + list(extra)
    for p in paths:
        if p and os.path.isfile(p):
            key = os.path.normcase(os.path.abspath(p))
            if key not in seen:
                seen.add(key)
                out.append(os.path.abspath(p))
    return out


def choose_method(binreq, osn, arch):
    for m in binreq.get("methods") or []:
        if m.get("os") and osn not in m["os"]:
            continue
        if m["method"] == "release" and arch not in (m.get("arch") or [arch]):
            continue
        if m.get("requires") and not C.find_tool(m["requires"]):
            continue
        return m
    return None


def install_plan(binreq, method, osn, arch):
    """(argv, installs_to, effect, hosts) for one install method."""
    name, version = binreq["name"], str(binreq["install_version"])
    exe = ".exe" if osn == "windows" else ""
    if method["method"] == "go":
        argv = [C.find_tool("go")] + [fill(a, version=version) for a in method["command"][1:]]
        bindir = C.go_bin_dir() or Path.home() / "go" / "bin"
        target = str(bindir / (name + exe))
        effect = "builds %s %s with Go and installs it to %s" % (name, version, target)
    elif method["method"] == "brew":
        brew = C.find_tool("brew")
        argv = [brew] + [fill(a, version=version) for a in method["command"][1:]]
        code, out = run_text([brew, "--prefix"], timeout=60)
        prefix = out.strip().splitlines()[-1] if code == 0 and out.strip() else "/opt/homebrew"
        target = str(Path(prefix) / "bin" / name)
        effect = "installs %s with Homebrew to %s. %s" % (name, target, method.get("unpinned") or "")
    else:
        dests = method.get("dest") or {}
        dest = Path(os.path.expanduser(os.path.expandvars(dests.get(osn) or dests["default"])))
        target = str(dest / (name + exe))
        argv = [sys.executable, str(Path(__file__).resolve().parent / "install_release.py"), binreq["id"], "--version", version]
        asset = fill(method["asset"], version=version, os=osn, arch=arch, exe=exe)
        effect = ("downloads %s from the %s %s release on GitHub, checks its SHA-256 against %s, then saves it to %s"
                  % (asset, method["repo"], fill(method["tag"], version=version), method["checksums"], target))
    return [a for a in argv if a], target, effect.strip(), list(method.get("hosts") or [])


def check_binary(binreq, osn, arch, extra_paths=()):
    """The item for one binary plus what the MCP check needs: the path to register and the planned install."""
    name = binreq["name"]
    label = "%s binary %s or later" % (name, binreq.get("min_version"))
    if binreq.get("allowed") is False:
        return item(binreq["id"], "machine", "%s binary" % name, "n/a", detail=binreq.get("reason")), None, None
    found = []
    for p in binary_candidates(name, extra_paths):
        found.append((p, C.tool_version([p, "--version"])))
    minimum = str(binreq["min_version"])
    good = [f for f in found if f[1] and C.compare_versions(f[1], minimum) >= 0]
    best = max(good or [f for f in found if f[1]] or found or [(None, None)],
               key=lambda f: C.version_sort_key(f[1] or "0"))
    path, version = best
    others = ["%s (%s)" % (p, v or "version unknown") for p, v in found if p != path]
    notes = [n["text"] for n in binreq.get("notes") or [] if version and C.compare_versions(version, str(n["below"])) < 0]
    detail = [binreq.get("needed_for") or ""]
    if path and not shutil.which(name):
        detail.append("Not on PATH; the scripts and the MCP registration use its absolute path.")
    if others:
        detail.append("Other copies: %s." % "; ".join(others))
    detail += notes
    if path and version and C.compare_versions(version, minimum) >= 0:
        return item(binreq["id"], "machine", label, "ok", found="%s at %s" % (version, path),
                    detail=sentences(*detail)), path, None
    status = "outdated" if path and version else "missing"
    if path and not version:
        detail.append("%s was found but `%s --version` failed." % (path, name))
    method = choose_method(binreq, osn, arch)
    planned = None
    if method:
        argv, target, effect, hosts = install_plan(binreq, method, osn, arch)
        planned = {"method": method["method"], "argv": argv, "installs_to": target, "effect": effect, "hosts": hosts,
                   "version": str(binreq["install_version"])}
        fix = {"by": "setup", "method": method["method"], "commands": [display_command(argv)], "installs_to": target,
               "effect": effect}
    else:
        fix = manual("No install method fits %s/%s. Install %s %s or later yourself into a user-level folder."
                     % (osn, arch, name, minimum))
    return item(binreq["id"], "machine", label, status, binreq.get("impact") or "degrades",
                found="%s at %s" % (version or "unknown version", path) if path else None,
                detail=sentences(*detail), fix=fix), path if status == "outdated" else None, planned


# --------------------------------------------------------------------------- machine: MCP servers

def claude_config_file():
    d = os.environ.get("CLAUDE_CONFIG_DIR")
    if d:
        return Path(os.path.expanduser(d)) / ".claude.json"
    main = Path.home() / ".claude.json"
    legacy = Path.home() / ".claude" / ".config.json"
    return legacy if legacy.is_file() and not main.is_file() else main


def read_json_file(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def entry_text(entry):
    if not isinstance(entry, dict):
        return ""
    return " ".join([str(entry.get("command") or entry.get("url") or "")] + [str(a) for a in entry.get("args") or []])


def find_registrations(server_name, binary, args, project_dirs):
    """[{scope, name, command, args, file}] for servers named server_name, or running `binary ... args`."""
    def matches(nm, entry):
        text = entry_text(entry).lower()
        return nm == server_name or (binary in text and all(a in text for a in args))

    found = []
    cfg = claude_config_file()
    data = read_json_file(cfg) if cfg.is_file() else None
    wanted = {norm_key(Path(d).resolve()) for d in project_dirs}
    if data:
        for nm, entry in (data.get("mcpServers") or {}).items():
            if matches(nm, entry):
                found.append(("user", nm, entry, str(cfg)))
        for key, proj in (data.get("projects") or {}).items():
            if isinstance(proj, dict) and norm_key(key) in wanted:
                for nm, entry in (proj.get("mcpServers") or {}).items():
                    if matches(nm, entry):
                        found.append(("local", nm, entry, "%s (project %s)" % (cfg, key)))
    for d in project_dirs:
        f = Path(d) / ".mcp.json"
        pdata = read_json_file(f) if f.is_file() else None
        for nm, entry in ((pdata or {}).get("mcpServers") or {}).items():
            if matches(nm, entry):
                found.append(("project", nm, entry, str(f)))
    out, seen = [], set()
    for scope, nm, entry, src in found:
        key = (scope, nm, src)
        if key not in seen:
            seen.add(key)
            out.append({"scope": scope, "name": nm, "command": (entry or {}).get("command") or (entry or {}).get("url"),
                        "args": [str(a) for a in (entry or {}).get("args") or []], "file": src})
    return out


SCOPE_LABELS = (("local", "local"), ("project", "project"), ("user", "user"), ("claude.ai", "claude.ai"))


def mcp_get(claude, name, cwd):
    """Effective registration from `claude mcp get <name>`: None when there is none, or {"error": ...}."""
    code, out = run_text([claude, "mcp", "get", name], cwd=cwd, timeout=120)
    if code is None:
        return {"error": "claude mcp get %s: %s" % (name, out)}
    if code != 0:
        if "No MCP server named" in out:
            return None
        return {"error": "claude mcp get %s exited %s: %s" % (name, code, C.redact_text(out.strip())[-300:])}
    info = {}
    for line in out.splitlines():
        m = re.match(r"^\s+(Scope|Status|Issue|Type|Command|Args|URL):[ \t]*(.*)$", line)
        if m:
            info[m.group(1).lower()] = m.group(2).strip()
    label = info.get("scope", "").lower()
    info["scope_key"] = next((key for prefix, key in SCOPE_LABELS if label.startswith(prefix)), label or None)
    status = info.get("status", "")
    info["state"] = ("connected" if "connected" in status.lower() and "fail" not in status.lower() else
                     "pending-approval" if "pending" in status.lower() else
                     "needs-auth" if "auth" in status.lower() else
                     "failed" if "fail" in status.lower() else
                     "disabled" if "disabled" in status.lower() else (status.lower() or None))
    return info


def command_exists(command):
    if not command:
        return False
    if os.path.isabs(command) or os.sep in command or "/" in command:
        return os.path.isfile(command)
    return bool(shutil.which(command))


def describe_reg(r):
    return "%s scope (%s %s; in %s)" % (r["scope"], r["command"], " ".join(r["args"]), r["file"])


def check_mcp(srv, claude, project_dirs, run_dir):
    """The MCP item, before the fix is attached (that needs the binary's result)."""
    name, label = srv["name"], "%s MCP server (%s scope)" % (srv["name"], srv.get("scope") or "user")
    if srv.get("allowed") is False:
        return item(srv["id"], "mcp", "%s MCP server" % name, "n/a", detail=srv.get("reason")), {}
    regs = find_registrations(name, srv["binary"], srv.get("args") or [], project_dirs)
    same_name = [r for r in regs if r["name"] == name]
    other_name = [r for r in regs if r["name"] != name]
    eff = mcp_get(claude, name, run_dir) if claude else None
    if eff and eff.get("error"):
        state_err, eff = eff["error"], None
    else:
        state_err = None
    ctx = {"regs": regs, "effective": eff, "claude": claude}
    shadowing = [r for r in same_name if r["scope"] in ("local", "project")]
    if eff and eff.get("scope_key") in ("local", "project") and not shadowing:
        shadowing = [{"scope": eff["scope_key"], "name": name, "command": eff.get("command"),
                      "args": (eff.get("args") or "").split(), "file": "claude mcp get"}]
    health = (eff or {}).get("state")
    health_text = {"connected": "connected", "failed": "fails to connect (%s)" % (eff or {}).get("issue", "no detail"),
                   "pending-approval": "waiting for approval of the project's .mcp.json server",
                   "needs-auth": "needs authentication"}.get(health, health)
    if shadowing:
        impact = "none" if health == "connected" else "degrades"
        detail = ("Registered at %s. A project or local registration takes precedence over user scope in that project, "
                  "so setup won't add or change anything for this name; only you should change it."
                  % "; ".join(describe_reg(r) for r in shadowing))
        active = (eff or {}).get("scope_key")
        if active and active not in {r["scope"] for r in shadowing}:
            detail += (" Claude Code currently uses the %s-scope registration here (%s), because the %s-scope one isn't active "
                       "yet (a .mcp.json server needs your approval first); once it is, it takes over."
                       % (active, health_text or "status unknown", shadowing[0]["scope"]))
        elif health_text:
            detail += " Status here: %s." % health_text
        return item(srv["id"], "mcp", label, "conflict", impact, found=describe_reg(shadowing[0]), detail=detail,
                    fix=manual("Keep it if it runs `osv-scanner experimental-mcp`; otherwise remove or rename it yourself, "
                               "for example `claude mcp remove %s --scope %s`." % (name, shadowing[0]["scope"]))), ctx
    user = [r for r in same_name if r["scope"] == "user"]
    reg = user[0] if user else None
    if not reg and eff and eff.get("scope_key") == "user":
        reg = {"scope": "user", "name": name, "command": eff.get("command"), "args": (eff.get("args") or "").split(),
               "file": "claude mcp get"}
    if not reg and other_name:
        reg = other_name[0]
        ctx["other_name"] = reg["name"]
    ctx["reg"] = reg
    if reg:
        ctx["stale"] = not command_exists(reg["command"])
        found = describe_reg(reg)
        if ctx["stale"]:
            return item(srv["id"], "mcp", label, "missing", srv.get("impact") or "degrades", found=found,
                        detail="Registered, but its command %s no longer exists, so the server can't start and the audit "
                               "would fall back. %s" % (reg["command"], srv.get("impact_why") or "")), ctx
        if ctx.get("other_name"):
            detail = "Registered under the name '%s' rather than '%s'; setup leaves it alone." % (reg["name"], name)
        else:
            detail = "Registered at user scope."
        if health_text:
            detail += " Status: %s." % health_text
        elif not claude:
            detail += " Connection status unknown: the claude CLI wasn't found."
        if state_err:
            detail += " %s" % state_err
        status, impact = ("missing", srv.get("impact") or "degrades") if health == "failed" else ("ok", "none")
        return item(srv["id"], "mcp", label, status, impact, found=found, detail=detail), ctx
    detail = "Not registered. %s" % (srv.get("impact_why") or "")
    if state_err:
        detail += " (%s)" % state_err
    return item(srv["id"], "mcp", label, "missing", srv.get("impact") or "degrades", detail=detail.strip()), ctx


def attach_mcp_fix(it, srv, ctx, bin_path, planned):
    """Fill in the MCP item's fix: register at user scope with the binary's absolute path (spec §2 step 4)."""
    if it["status"] in ("ok", "n/a", "conflict"):
        return
    claude = ctx.get("claude")
    target = planned["installs_to"] if planned else bin_path
    if ctx.get("other_name"):
        it["fix"] = manual("The server registered as '%s' fails to start. Fix or remove it yourself; setup doesn't change "
                           "servers under other names." % ctx["other_name"])
        return
    if not claude:
        it["fix"] = manual("The claude CLI wasn't found. Register `%s %s` as an MCP server named %s in your agent's "
                           "settings." % (target or srv["binary"], " ".join(srv.get("args") or []), srv["name"]))
        return
    if not target:
        it["fix"] = manual("Install %s first; no install method fits this machine." % srv["binary"])
        return
    reg = ctx.get("reg")
    expected = [target] + list(srv.get("args") or [])
    if reg and not ctx.get("stale") and same_file(reg["command"], target) and reg["args"] == expected[1:]:
        it["fix"] = manual("It is registered with the expected command but fails to start (%s). Run `%s %s` yourself to "
                           "see why." % ((ctx.get("effective") or {}).get("issue") or "no detail", target,
                                         " ".join(srv.get("args") or [])))
        return
    steps = []
    if reg:  # stale or different command: replace the user-scope registration
        steps.append([claude, "mcp", "remove", srv["name"], "--scope", "user"])
    steps.append([claude, "mcp", "add", "--scope", "user", srv["name"], "--"] + expected)
    it["fix"] = {"by": "setup", "commands": [display_command(s) for s in steps], "argv": steps,
                 "effect": "registers the server at user scope with the binary's absolute path, outside the project"}


# --------------------------------------------------------------------------- machine: optional scanners

def check_scanner(sc, ecosystems, private_packages):
    sid = sc["id"]
    if sc.get("allowed") is False:
        return item("scanner:%s" % sid, "scanner", sid, "n/a", detail=sc.get("reason"))
    ecos = sc.get("ecosystems")
    if ecosystems is not None and ecos != "all" and not set(ecos or []) & set(ecosystems):
        return item("scanner:%s" % sid, "scanner", sid, "n/a", detail="No %s files in this project." % "/".join(ecos or []))
    found = None
    for cmd in sc.get("commands") or []:
        parts = cmd.split()
        exe = C.find_tool(parts[0])
        if not exe:
            continue
        version = C.tool_version([exe] + parts[1:] + ["--version"])
        if len(parts) > 1 and not version:
            continue  # "cargo audit" exists only when the cargo-audit plugin is installed
        found = (exe, version, cmd)
        break
    note = ""
    if private_packages and sid in ("npm-audit", "pip-audit", "composer-audit"):
        note = " This project has private packages, so the audit will skip it (it sends package names to a public service)."
    if found:
        return item("scanner:%s" % sid, "scanner", sid, "ok", found="%s at %s" % (found[1] or "version unknown", found[0]),
                    detail=("Runs read-only in Step 4.4." + note).strip())
    return item("scanner:%s" % sid, "scanner", sid, "missing", detail=("Not installed." + note).strip(), fix=manual(OPTIONAL_HINT))


# --------------------------------------------------------------------------- network

def policy_hosts():
    hosts = []
    try:
        rules = C.load_rules("support_sources")
    except (OSError, ValueError):
        return hosts
    for pol in rules.get("policies") or []:
        h = (urllib.parse.urlsplit(str(pol.get("url") or "")).hostname or "").lower()
        if h:
            hosts.append({"host": h, "for": "Support policy page: %s" % pol.get("name"), "ecosystems": "all"})
    return hosts


def download_blocked(hosts, unreachable):
    """The unreachable hosts that stop a download: the first host (the one the install command contacts), or
    every other host at once (the hosts it may be redirected to, or that verify the download)."""
    if not hosts:
        return []
    if hosts[0] in unreachable:
        return [hosts[0]]
    rest = hosts[1:]
    return rest if rest and all(h in unreachable for h in rest) else []


def check_hosts(hosts, timeout):
    results = {}
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {h: ex.submit(C.host_reachable, "https://%s/" % h, timeout) for h in hosts}
        for h, fut in futures.items():
            try:
                results[h] = fut.result()
            except Exception as e:  # noqa: BLE001 - a broken check is reported, never fatal
                results[h] = (False, str(e))
    return results


# --------------------------------------------------------------------------- project

def analyse_project(root):
    """detect_inventory.py's reading of the project, in memory: offline, nothing written."""
    import detect_inventory as D
    inv = D.Inventory(root, SimpleNamespace(offline=True, no_transitive=False, internal=[], mirror_public=False))
    inv.run()
    return inv.to_json(C.now_iso())


def project_items(inv):
    items = []
    n_private = inv.get("private_packages") or 0
    maven_private = inv.get("maven_private") or []
    if n_private:
        regs = ["%s %s (%s)" % (r.get("ecosystem"), r.get("host"), r.get("evidence"))
                for r in (inv.get("registries") or {}).get("private") or []]
        names = [lib["name"] for lib in inv.get("libraries") or [] if lib.get("private")]
        examples = ", ".join(names[:3]) + (" and %d more" % (len(names) - 3) if len(names) > 3 else "")
        items.append(item("project:private-packages", "project", "Private packages: %d" % n_private, "gap", "degrades",
                          found=sentences("Registries: %s" % "; ".join(regs) if regs else "", "Packages: %s" % examples if names else ""),
                          detail="Private packages are never sent to public services (§9): their support status will be unknown, "
                                 "they get no OSV lookups, and the osv-scanner MCP scan, the osv-scanner CLI and the scanners that "
                                 "send package names to public services are skipped for the whole project; query_osv.py still "
                                 "checks the public packages.",
                          fix=manual("Nothing setup can change: this is how the audit keeps internal names private.")))
    for i, m in enumerate((inv.get("registries") or {}).get("mirrors") or []):
        items.append(item("project:mirror:%d" % (i + 1), "project", "Registry mirror: %s %s" % (m.get("ecosystem"), m.get("host")),
                          "gap", "degrades", found=m.get("evidence"),
                          detail="One registry serves all %d %s packages, public and internal alike, so the audit treats them all "
                                 "as private unless you say which names are internal (open question 4)." % (m.get("packages") or 0, m.get("ecosystem")),
                          fix=manual("When the audit asks, name the internal packages (--internal PATTERN --mirror-public), or leave "
                                     "them all private.")))
    for i, entry in enumerate(maven_private):
        items.append(item("project:maven-private:%d" % (i + 1), "project", "Maven private repository", "gap", "degrades", found=entry,
                          detail="Neither the osv-scanner MCP scan nor the CLI will run (both would send internal artifacts to "
                                 "OSV.dev and deps.dev), so transitive dependencies of pom.xml won't be resolved; public artifacts "
                                 "are still checked by query_osv.py (§9).",
                          fix=manual("Nothing setup can change. A Maven lockfile-style export of resolved versions would widen coverage.")))
    for i, g in enumerate(inv.get("gaps") or []):
        items.append(item("project:gap:%d" % (i + 1), "project", "Coverage gap", "gap", "degrades", detail=g,
                          fix=manual("Committing a lockfile (or resolved versions) for these manifests closes the gap.")))
    for u in inv.get("ecosystems_unsupported") or []:
        items.append(item("project:unsupported:%s" % u.get("ecosystem"), "project", "Unsupported ecosystem: %s" % u.get("ecosystem"),
                          "gap", "degrades", found=", ".join(u.get("files") or []) or None,
                          detail="Seen but not analyzed; the report lists it under coverage.ecosystems_unsupported.",
                          fix=manual("Not supported by this skill.")))
    if inv.get("go_modules"):
        items.append(item("project:go", "project", "Go modules", "gap", "none", found=", ".join(inv["go_modules"]),
                          detail="The osv-scanner MCP scan always runs Go call analysis, so it is skipped for this project and the "
                                 "osv-scanner CLI runs with --no-call-analysis=all instead. Go reachability is checked by hand "
                                 "(open question 13).",
                          fix=manual("Nothing to do.")))
    return items


# --------------------------------------------------------------------------- assemble

def build(args):
    req = C.load_rules("requirements")
    osn, arch = current_os(), current_arch()
    target = Path(args.path).resolve() if args.path else None
    if target and not target.is_dir():
        raise SystemExit("error: %s is not a directory" % target)
    run_dir = Path.cwd()
    project_dirs = C.dedupe([d for d in [run_dir, git_root(run_dir), target, git_root(target) if target else None] if d])
    claude = C.find_tool("claude")

    inv = analyse_project(target) if target else None
    ecosystems = list(inv.get("ecosystems") or []) if inv else None
    private_packages = (inv or {}).get("private_packages") or 0
    go_project = bool((inv or {}).get("go_modules"))

    items = [check_python(req), check_skill_files(req)]
    binreqs = {b["id"]: b for b in req.get("binaries") or []}
    servers = {s["id"]: s for s in req.get("mcp_servers") or []}

    mcp_results = {}
    for sid, srv in servers.items():
        mcp_results[sid] = check_mcp(srv, claude, project_dirs, run_dir)

    bin_results = {}
    for bid, b in binreqs.items():
        extra = []
        for sid, (_it, ctx) in mcp_results.items():
            reg = (ctx or {}).get("reg")
            if servers[sid].get("binary") == b.get("name") and reg and command_exists(reg["command"]):
                extra.append(shutil.which(reg["command"]) or reg["command"])
        bin_results[bid] = check_binary(b, osn, arch, extra)

    for bid, (it, _p, _pl) in bin_results.items():
        items.append(it)
    for sid, (it, ctx) in mcp_results.items():
        srv = servers[sid]
        bid = next((b for b, br in binreqs.items() if br.get("name") == srv.get("binary")), None)
        if bid and srv.get("allowed") is not False:
            _bit, bpath, planned = bin_results[bid]
            attach_mcp_fix(it, srv, ctx, bpath, planned)
        items.append(it)

    # project-specific impact of the osv-scanner tools
    for it in items:
        if it["id"] in ("osv-scanner", "osv-scanner-mcp") and it["status"] not in ("ok", "n/a") and inv is not None:
            if private_packages:
                it["impact"] = "none"
                add_detail(it, "For this project it doesn't matter: it has private packages, so neither the MCP scan nor the "
                               "CLI will run")
            elif it["id"] == "osv-scanner-mcp" and go_project:
                it["impact"] = "none"
                add_detail(it, "For this project the MCP scan is skipped anyway (Go modules, open question 13)")
        if it["id"] in ("gopls", "gopls-mcp"):
            if go_project:
                add_detail(it, "This project has Go modules, so it would otherwise apply")
            elif inv is not None:
                it["detail"] = sentences("Not a Go project", it.get("detail"))

    for sc in req.get("optional_scanners") or []:
        items.append(check_scanner(sc, ecosystems, private_packages))

    # network
    hosts = list(req.get("hosts") or []) + [h for h in policy_hosts() if h["host"] not in {x["host"] for x in req.get("hosts") or []}]
    setup_hosts = []
    if args.mode == "setup":
        for bid, (it, _p, planned) in bin_results.items():
            for h in (planned or {}).get("hosts") or []:
                if h not in setup_hosts and h not in {x["host"] for x in hosts}:
                    setup_hosts.append(h)
    reach = check_hosts([h["host"] for h in hosts] + setup_hosts, args.timeout)
    for h in hosts:
        ok, why = reach[h["host"]]
        relevant = ecosystems is None or h.get("ecosystems") == "all" or bool(set(h.get("ecosystems") or []) & set(ecosystems))
        if ok:
            items.append(item("host:%s" % h["host"], "network", h["host"], "ok", found=why, detail=h.get("for")))
        else:
            items.append(item("host:%s" % h["host"], "network", h["host"], "unreachable", "degrades" if relevant else "none",
                              found=why, detail="%s. Unreachable, so that part of an audit would run offline%s."
                              % (h.get("for"), "" if relevant else " (not used by this project)"),
                              fix=manual("Check the network, proxy (HTTPS_PROXY) or firewall; setup never changes them.")))
    for h in setup_hosts:
        ok, why = reach[h]
        items.append(item("host:%s" % h, "network", "%s (setup download)" % h, "ok" if ok else "unreachable",
                          "none" if ok else "degrades", found=why, detail="Download host for the install plan.",
                          fix=None if ok else manual("Check the network, proxy or firewall; without it the binary can't be downloaded.")))
    unreachable = {h for h, (ok, _why) in reach.items() if not ok}

    if inv is not None:
        items.extend(project_items(inv))

    # plan: installs first, then registrations, then the version check
    plan, notes = [], []
    for bid, (it, _p, planned) in bin_results.items():
        if not planned or (it.get("fix") or {}).get("by") != "setup":
            continue
        down = download_blocked(planned["hosts"], unreachable) if args.mode == "setup" else []
        if down:
            it["fix"]["skipped"] = "download host unreachable: %s" % ", ".join(down)
            notes.append("%s can't be downloaded now (%s unreachable); setup will skip installing it." % (bid, ", ".join(down)))
            continue
        plan.append({"for": bid, "command": display_command(planned["argv"]), "argv": planned["argv"], "effect": planned["effect"]})
    installs = {p["for"] for p in plan}
    for it in items:
        if it["group"] != "mcp" or (it.get("fix") or {}).get("by") != "setup":
            continue
        srv = servers.get(it["id"]) or {}
        bid = next((b for b, br in binreqs.items() if br.get("name") == srv.get("binary")), None)
        bit = bin_results.get(bid, (None, None, None))[0] if bid else None
        if bit and bit["status"] != "ok" and bid not in installs:
            it["fix"]["skipped"] = "%s isn't installed and can't be installed now" % srv.get("binary")
            continue
        for argv, cmd in zip(it["fix"]["argv"], it["fix"]["commands"]):
            plan.append({"for": it["id"], "command": cmd, "argv": argv, "effect": it["fix"]["effect"]})
    for bid in installs:
        planned = bin_results[bid][2]
        plan.append({"for": bid, "command": display_command([planned["installs_to"], "--version"]),
                     "argv": [planned["installs_to"], "--version"],
                     "effect": "checks the installed version is %s" % planned["version"]})
    if any(p["for"].endswith("-mcp") for p in plan):
        notes.append("After registering, start a new Claude Code session so the MCP tools load, and check them with /mcp.")
    for i, p in enumerate(plan, 1):
        p["step"] = i

    worst = max((IMPACT_RANK[it["impact"]] for it in items), default=0)
    verdict, verdict_text = VERDICTS[worst]
    suggest = any(it["impact"] != "none" and (it.get("fix") or {}).get("by") == "setup" and not (it.get("fix") or {}).get("skipped")
                  for it in items)
    return {
        "tool": TOOL, "generated_at": C.now_iso(), "mode": args.mode,
        "platform": {"os": osn, "arch": arch, "python": platform.python_version(), "claude_cli": claude},
        "target": None if inv is None else {"path": C.posix(target), "ecosystems": ecosystems, "private_packages": private_packages,
                                            "go_modules": inv.get("go_modules") or []},
        "items": items, "plan": plan, "notes": notes,
        "counts": {s: sum(1 for it in items if it["status"] == s) for s in ("ok", "missing", "outdated", "conflict", "unreachable", "n/a", "gap")},
        "verdict": verdict, "verdict_text": verdict_text, "exit_code": worst, "suggest_setup": suggest,
    }


def render_text(rep):
    lines = ["Setup check (%s): %s" % ("dry run" if rep["mode"] == "dry" else "setup", rep["verdict_text"])]
    if rep.get("target"):
        t = rep["target"]
        lines.append("Project: %s (ecosystems: %s)" % (t["path"], ", ".join(t["ecosystems"]) or "none"))
    hosts = [it for it in rep["items"] if it["group"] == "network"]
    for it in rep["items"]:
        if it["group"] == "network" and it["status"] == "ok":
            continue
        fix = it.get("fix") or {}
        how = "; ".join(fix.get("commands") or []) if fix.get("by") == "setup" else ("manual" if fix else "")
        lines.append("  %-11s %-8s %-46s %s" % (it["status"], it["impact"], it["name"][:46], it.get("found") or ""))
        if it.get("detail") and it["status"] != "ok":
            lines.append("  %20s %s" % ("", it["detail"]))
        if how:
            lines.append("  %20s fix: %s%s" % ("", how, (" (%s)" % fix["skipped"]) if fix.get("skipped") else ""))
    lines.append("Network: %d of %d hosts reachable" % (sum(1 for h in hosts if h["status"] == "ok"), len(hosts)))
    if rep["plan"]:
        lines.append("Plan (--setup runs these only after you approve):")
        lines += ["  %d. %s" % (p["step"], p["command"]) for p in rep["plan"]]
    for n in rep.get("notes") or []:
        lines.append("Note: %s" % n)
    if rep["suggest_setup"] and rep["mode"] == "dry":
        lines.append("Run /dependency-audit --setup to fix what setup can fix.")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check what a dependency audit needs on this machine (read-only).")
    ap.add_argument("path", nargs="?", help="project to check for applicable tools and known gaps (optional)")
    ap.add_argument("--mode", choices=("dry", "setup"), default="dry",
                    help="dry (--setup-dry, the default) or setup (also checks the plan's download hosts)")
    ap.add_argument("--format", choices=("json", "text"), default="json")
    ap.add_argument("--timeout", type=float, default=8.0, help="seconds per host check (default 8)")
    args = ap.parse_args(argv)
    rep = build(args)
    print(json.dumps(rep, indent=2, ensure_ascii=False) if args.format == "json" else render_text(rep))
    return rep["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
