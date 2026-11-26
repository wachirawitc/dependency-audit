# Setup: `--setup` and `--setup-dry`

Both modes start from `scripts/setup_check.py`, which only reads: it installs nothing, never runs
`claude mcp add` or `remove`, and writes no files. Its only network traffic is one plain HTTPS request
per host in `rules/requirements.yaml` (no package names), plus the health check `claude mcp get` does on
the osv-scanner server. Neither mode audits anything or writes report files.

`<skill>` below is the folder holding SKILL.md. `[path]` is optional: with it, the check also reads the
project's file names and manifests (offline) to say which optional tools apply and which gaps an audit
will hit whatever is installed.

## --setup-dry [path]

Answers one question: will an audit on this machine, and in this project, run smoothly?

1. Run `python <skill>/scripts/setup_check.py [path] --format json`. The exit code matches the verdict:
   0 Ready, 1 Ready with gaps (something degrades the audit), 2 Not ready (something blocks it).
2. Report in chat, verdict first. Give one row per item that isn't `ok`: status, impact, what it means for
   an audit, and the fix (the command `--setup` would run, or "manual"). Collapse the `ok` items into a
   line, for example "Python 3.14.9, skill files and 17 of 17 hosts OK".
3. If `suggest_setup` is true, suggest `/dependency-audit --setup`.

Don't install, register or write anything in this mode, even if the fix looks trivial.

```
Setup check: Ready with gaps

  missing   degrades  osv-scanner 2.2.4+        not installed; audits fall back to OSV.dev batch queries
                                                fix: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0
  missing   degrades  osv-scanner MCP server    not registered; audits fall back to the CLI
                                                fix: claude mcp add --scope user osv-scanner -- C:\Go\bin\osv-scanner.exe experimental-mcp
  gap       degrades  Maven private repository  pom.xml: repository nexus.acme.internal; no MCP scan or CLI for this project (manual)
  n/a       none      gopls MCP server          not used (open question 13)

OK: Python 3.14.9, skill files, 17 of 17 hosts reachable, npm and dotnet scanners installed.
Run /dependency-audit --setup to fix what setup can fix.
```

## --setup [path]

Setup is the only mode that installs anything. It changes only the user's own environment (user-level
folders and the user-scope MCP configuration), never the project.

1. **Check.** Run `python <skill>/scripts/setup_check.py [path] --mode setup --format json`. This also
   checks the download hosts the plan needs and leaves out downloads that can't work.
2. **Nothing to do?** If `plan` is empty, say everything is already in place and stop. Re-running setup
   on a ready machine changes nothing.
3. **Show the plan and wait.** List each step in `plan` with its exact `command` and `effect` (what gets
   installed where, at which version), then the items setup won't touch (status `conflict`, `gap`, Python,
   optional scanners), each with its manual hint. Ask the user to approve. Run nothing until they do; if
   they approve only part, run only that part.
4. **Run the approved steps** in order, exactly as given (`argv` holds the precise arguments; in PowerShell,
   put `&` before a command whose first token is a quoted path). Install methods, in order of preference:
   `go install` when Go is present, Homebrew on macOS and Linux, else `install_release.py`, which downloads
   the pinned GitHub release and checks its SHA-256 against the release's checksums file before saving it.
   - If a step fails, show its error output, skip the steps that depend on it (the registration of a binary
     that didn't install, its version check), and carry on with the rest. Don't switch to another install
     method unless the user approves it.
   - Never use `sudo` or admin rights, never pipe a download into a shell, and never install outside
     user-level folders.
5. **Verify.** Run `setup_check.py` again with the same `[path]` (without `--mode setup`) and report the statuses. Then tell the
   user to **start a new session** so the newly registered MCP tools load, and to check them with `/mcp`.
6. **Report** what was installed, registered and skipped, and why.

## Rules

- Register MCP servers at **user scope** with the binary's **absolute path**, so the server works in
  every project, stays out of the repository's `.mcp.json`, and starts even when the client's PATH
  differs from the shell's (common on Windows). The plan's commands already do this.
- A server named `osv-scanner` at project or local scope is a `conflict`: report it and change nothing
  for that name. That registration takes precedence in its project, and only the user should change it.
- A user-scope registration with the same command is left alone. A stale one (its binary is gone) is
  replaced: the plan removes it and adds it again with the new path.
- Never register servers the skill doesn't use. gopls stays off, and so does govulncheck: both load Go packages
  and may download modules (open question 13).
- Optional scanners (`pip-audit`, `cargo audit`, `trivy`, …) and Python itself are reported, never
  installed (open questions 10 and 16).
- Without the `claude` CLI (another agent), the MCP fix is manual: tell the user to register
  `<absolute path to osv-scanner> experimental-mcp` as an MCP server named `osv-scanner` in their agent.
- Without network, downloads are left out of the plan; what is already installed can still be registered.

## Statuses and impact

| Status | Meaning |
|---|---|
| `ok` | Present and recent enough, or reachable |
| `missing` | Not installed or not registered, or registered but its command is gone or fails to start |
| `outdated` | Installed below the minimum version |
| `conflict` | An MCP server with the same name at project or local scope |
| `unreachable` | A host the audit or the download needs can't be reached |
| `n/a` | Doesn't apply (gopls and govulncheck; a scanner for an ecosystem the project doesn't use) |
| `gap` | A known coverage gap in the project that no install fixes (private registries, Maven private repositories, manifests without lockfiles, unsupported ecosystems, Go call analysis) |

Impact: `blocks` (the audit can't produce valid reports: Python or the skill's files), `degrades` (the
audit runs with fallbacks or gaps), `none`. A missing osv-scanner has no impact on a project with private
packages, because neither the MCP scan nor the CLI may run there anyway; a missing MCP server has none on a
project with Go modules, where the MCP scan is skipped.
