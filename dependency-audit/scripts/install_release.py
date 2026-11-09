#!/usr/bin/env python3
"""Install a pinned release binary for --setup (spec §2 Setup step 3). Run it only as part of a plan
the user has approved.

Usage:
    python install_release.py <id> [--version V] [--dest DIR] [--os OS] [--arch ARCH]

<id> is a binary in rules/requirements.yaml that has a `release` method (osv-scanner). The script:
  1. downloads the release's checksums file, and the asset for this OS and architecture, from
     https://github.com/<repo>/releases/download/<tag>/ into a temporary file inside DEST;
  2. checks the asset's SHA-256 against the checksums file, and deletes the download on a mismatch;
  3. only then makes it executable and moves it to DEST/<name>[.exe], replacing an older copy there;
  4. runs `<binary> --version` and checks that it reports the expected version.
Nothing runs before the checksum matches, no download is piped into a shell, and nothing outside DEST
changes. DEST defaults to the requirement's user-level folder (%LOCALAPPDATA%\\Programs\\<name> on
Windows, ~/.local/bin elsewhere). --version defaults to install_version.

Prints one JSON object. Exit code 0 when installed and verified, 1 otherwise. Standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

MAX_BYTES = 500 * 1024 * 1024
ARCH_ALIASES = {"x86_64": "amd64", "amd64": "amd64", "x64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def current_os() -> str:
    return {"windows": "windows", "darwin": "darwin", "linux": "linux"}.get(platform.system().lower(), platform.system().lower())


def current_arch() -> str:
    machine = platform.machine().lower()
    if os.name == "nt":  # a 64-bit Windows can run an x64 Python under emulation; ask Windows itself
        machine = (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or machine).lower()
    return ARCH_ALIASES.get(machine, machine)


def expand_dest(template: str) -> Path:
    return Path(os.path.expanduser(os.path.expandvars(template)))


def release_method(req: dict) -> dict:
    for m in req.get("methods") or []:
        if m.get("method") == "release":
            return m
    raise SystemExit("%s has no release method in rules/requirements.yaml" % req["id"])


def fill(template: str, **values) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: values.get(m.group(1), m.group(0)), template)


def open_url(url: str, timeout: float = 60):
    # No Accept-Encoding: the asset must arrive byte for byte as published. urllib follows GitHub's
    # redirect to its download host and honours the HTTPS_PROXY environment variable.
    req = urllib.request.Request(url, headers={"User-Agent": C.USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def download(url: str, dest_file: Path) -> str:
    """Stream url into dest_file and return its SHA-256 (hex)."""
    digest, size = hashlib.sha256(), 0
    with open_url(url) as resp, open(dest_file, "wb") as fh:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError("download is larger than %d MB" % (MAX_BYTES >> 20))
            digest.update(chunk)
            fh.write(chunk)
    return digest.hexdigest()


def parse_checksums(text: str) -> dict:
    """'<sha256>  <file>' lines (sha256sum format; a leading '*' marks binary mode) -> {file: sha256}."""
    sums = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(\S.*?)\s*$", line)
        if m:
            sums[m.group(2)] = m.group(1).lower()
    return sums


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Install a pinned, checksum-verified release binary (used by --setup).")
    ap.add_argument("id", help="binary id in rules/requirements.yaml, for example osv-scanner")
    ap.add_argument("--version", help="release version (default: install_version)")
    ap.add_argument("--dest", help="install folder (default: the requirement's user-level folder)")
    ap.add_argument("--os", dest="os_name", help="override the detected OS (windows, darwin, linux)")
    ap.add_argument("--arch", help="override the detected architecture (amd64, arm64)")
    args = ap.parse_args(argv)

    reqs = {b["id"]: b for b in C.load_rules("requirements").get("binaries") or []}
    if args.id not in reqs:
        print("unknown id %r; choose from: %s" % (args.id, ", ".join(sorted(reqs))), file=sys.stderr)
        return 1
    req = reqs[args.id]
    method = release_method(req)
    os_name, arch = args.os_name or current_os(), args.arch or current_arch()
    version = (args.version or req["install_version"]).lstrip("v")
    exe = ".exe" if os_name == "windows" else ""
    result = {"id": args.id, "version": version, "os": os_name, "arch": arch, "status": "failed"}

    def fail(message: str) -> int:
        result["error"] = message
        print(json.dumps(result, indent=2))
        return 1

    if os_name not in (method.get("os") or [os_name]) or arch not in (method.get("arch") or [arch]):
        return fail("no %s release asset for %s/%s" % (args.id, os_name, arch))
    if C.compare_versions(version, req["min_version"]) < 0:
        return fail("version %s is below the minimum %s" % (version, req["min_version"]))

    dests = method.get("dest") or {}
    dest = Path(args.dest) if args.dest else expand_dest(dests.get(os_name) or dests["default"])
    tag = fill(method["tag"], version=version)
    base = "https://github.com/%s/releases/download/%s/" % (method["repo"], tag)
    asset = fill(method["asset"], version=version, os=os_name, arch=arch, exe=exe)
    target = dest / (req["name"] + exe)
    result.update(asset=asset, url=base + asset, checksums_url=base + method["checksums"], dest=str(target))

    try:
        with open_url(base + method["checksums"], timeout=30) as resp:
            sums = parse_checksums(resp.read(1 << 20).decode("utf-8", errors="replace"))
    except (urllib.error.URLError, OSError, ValueError) as e:
        return fail("could not download the checksums file %s: %s" % (base + method["checksums"], e))
    expected = sums.get(asset)
    if not expected:
        return fail("the checksums file lists no entry for %s" % asset)

    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return fail("could not create %s: %s" % (dest, e))
    fd, tmp_name = tempfile.mkstemp(prefix=".%s-" % req["name"], suffix=".download", dir=dest)
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        try:
            actual = download(base + asset, tmp)
        except (urllib.error.URLError, OSError, ValueError) as e:
            return fail("download failed: %s" % e)
        result["sha256"] = actual
        if actual != expected:
            return fail("SHA-256 mismatch for %s: expected %s from %s, got %s; the download was deleted"
                        % (asset, expected, method["checksums"], actual))
        if os.name != "nt":
            tmp.chmod(0o755)
        try:
            os.replace(tmp, target)
        except PermissionError as e:
            return fail("could not replace %s (%s). If an MCP server is running this binary, close the Claude Code "
                        "sessions that use it and run the command again." % (target, e))
    finally:
        if tmp.exists():
            tmp.unlink()

    reported = C.tool_version([str(target), "--version"])
    result["reported_version"] = reported
    if not reported or C.compare_versions(reported, version) != 0:
        return fail("installed %s, but `%s --version` reported %s instead of %s" % (target, req["name"], reported, version))
    result["status"] = "installed"
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
