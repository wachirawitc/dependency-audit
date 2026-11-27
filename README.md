# dependency-audit

An agent skill that audits a project's dependencies and writes the result as both JSON and HTML.
For every run it reports:

- **Inventory**: the libraries, frameworks and runtimes the project uses, each with its support
  status (supported, security-only, end-of-life, deprecated, unmaintained or unknown).
- **Vulnerabilities**: known advisories affecting those dependencies, plus out-of-support items that
  need action, each with severity, evidence and a fix.

The audit is static and read-only. It does not review first-party code, scan for secrets, or check
Docker, CI or infrastructure configuration.

> **This is a read-only mirror.** The code is developed on GitLab and synced here from the
> `develop` branch with [Copybara](https://github.com/google/copybara). Changes pushed directly to
> this repository are overwritten by the next sync.

See [`samples/dependency-report.html`](samples/dependency-report.html) and
[`samples/dependency-report.json`](samples/dependency-report.json) for example output (fictional project).

## How it works

Scripts produce the facts; the agent supplies the judgment.

| Step | Script | What it does |
|---|---|---|
| 1. Inventory | `detect_inventory.py` | Parses manifests and lockfiles (npm, PyPI, Maven/Gradle including Android and Kotlin, Go, Cargo, RubyGems, Packagist, NuGet, Pub, CocoaPods/SwiftPM, container base images, vendored JS/CSS). Gradle builds without a `gradle.lockfile` get their transitive dependencies resolved from published Maven metadata |
| 2. Support status | `check_support.py` | End-of-life, deprecation and maintenance status from endoflife.date and the package registries |
| 3. Vulnerabilities | `run_scanners.py`, `query_osv.py` | osv-scanner (MCP server or CLI) and other installed scanners; every advisory confirmed against OSV.dev |
| 4. Draft | `build_report.py draft` | Drafts findings with IDs and triage hints |
| 5. Triage | (agent) | Reachability, severity adjustments, false positives, summary, recorded in `triage.json` |
| 6. Report | `build_report.py build`, `validate_report.py`, `render_html.py` | Builds the JSON, validates it against the schema, renders the HTML from it |

Key guarantees (full list in [`dependency-audit/SKILL.md`](dependency-audit/SKILL.md)):

- **The skill never uploads source code.** Its scripts, scanners and tool calls send no file
  content, excerpt or hash from the audited repository anywhere: osv-scanner and trivy read only a
  staged copy of the manifests and lockfiles (`raw/scan-input/`), never the project, and the reports
  stay on local disk. The one exception is inherent to any agent: files the agent reads during
  triage (to check reachability) are part of its session with the model provider.
- Advisory IDs and EOL dates come only from sources fetched during the run, never from the model's memory.
- Private or internal package names are never sent to public services.
- The project is never modified, built or executed, and no `osv-scanner.toml` is written.
- Registry credentials found in the project are shown only in redacted form (`npm_…(40)`).
- Repository text that tries to steer the audit is reported as a `prompt-injection-attempt` finding.

## Requirements

The source of truth for everything below is
[`dependency-audit/rules/requirements.yaml`](dependency-audit/rules/requirements.yaml), which `--setup-dry`
checks.

| Requirement | Version | If it's missing | Installed by `--setup` |
|---|---|---|---|
| Python | 3.11 or later (`tomllib`); standard library only, no `pip install` | **Blocks**: no script runs | No, install it yourself |
| [osv-scanner](https://github.com/google/osv-scanner) binary | 2.2.4 or later; setup installs 2.7.0 | Degrades: vulnerabilities come only from OSV.dev batch queries over the inventory, which misses packages osv-scanner resolves itself (for example `pom.xml` transitive dependencies) | Yes |
| osv-scanner MCP server, named `osv-scanner`, running `osv-scanner experimental-mcp` | same binary | Degrades: the audit falls back to the osv-scanner CLI | Yes, at user scope with the binary's absolute path |
| Network access (see below) | | Degrades: that part of the audit runs as `--offline` | n/a |

Notes:

- osv-scanner below 2.3.2 works, but its `get_vulnerability_details` MCP tool fails; the audit reads the
  saved OSV records instead.
- On a project with private or internal packages, or with Go modules, the MCP scan doesn't run anyway,
  so a missing osv-scanner MCP server costs nothing there.
- Registering the MCP server automatically needs the `claude` CLI. With another agent, register
  `<absolute path to osv-scanner> experimental-mcp` as an MCP server named `osv-scanner` yourself.

**Network.** Only public package names and versions are sent, over HTTPS, never source code, to:

- `api.osv.dev` (advisories) and `endoflife.date` (runtime and framework end-of-life dates)
- `api.github.com` and `gitlab.com` (archived flag and last release, for the unmaintained check)
- the registry of each ecosystem the project uses: `registry.npmjs.org`, `pypi.org`, `repo1.maven.org`,
  `dl.google.com`, `api.deps.dev` (Maven), `proxy.golang.org`, `crates.io`, `index.crates.io`, `rubygems.org`,
  `repo.packagist.org`, `api.nuget.org`, `pub.dev`, `trunk.cocoapods.org`
- for Gradle builds without a lockfile (Android included), `repo1.maven.org` and `dl.google.com`
  again, during the inventory step, to read the published POM and Gradle module metadata; skipped
  offline, with `--no-transitive`, and when a private Maven repository is configured
- the support-policy pages listed in [`dependency-audit/rules/support_sources.yaml`](dependency-audit/rules/support_sources.yaml)

With no network, use `--offline`: support statuses become `unknown` and no advisory IDs are reported.

**Optional scanners.** When installed, these also run, read-only, each with a scratch folder as its working
directory so repository config can't steer it: `npm audit`, `pip-audit`, `cargo audit`, `bundle-audit`,
`composer audit`, `dotnet list package --vulnerable` and `trivy`. trivy, like osv-scanner, reads only
`raw/scan-input/`, a copy of the manifests and lockfiles. Setup reports them but never installs them. Scanners
that would send package names to a public service are skipped when the project has private packages.
`govulncheck` and `gopls` are never used, because they load Go packages and may download modules.

Check and install the requirements with the skill itself:

```
/dependency-audit --setup-dry [path]   # report what's missing and how it affects an audit; changes nothing
/dependency-audit --setup [path]       # install and register what's missing, after you approve the plan
```

Setup installs only into user-level folders and registers MCP servers at user scope. It never uses
`sudo` and never touches the project.

## Installation

Copy (or symlink) the `dependency-audit/` folder into your agent's skills directory, for example
`~/.claude/skills/dependency-audit` for Claude Code, then run `/dependency-audit --setup-dry`.

## Usage

```
/dependency-audit [path] [--out <dir>] [--offline] [--severity <min>] [--no-transitive] [--fail-on <severity>] [--unmaintained-months <n>]
```

| Argument | Default | Effect |
|---|---|---|
| `path` | current directory | Project root to audit |
| `--out <dir>` | `./dependency-audit-out` | Folder for the reports and `raw/` evidence |
| `--offline` | off | No network lookups; support statuses `unknown`, vulnerabilities unverified |
| `--severity <min>` | `info` | Leave out findings below `critical`, `high`, `medium`, `low` or `info` |
| `--no-transitive` | off | Report direct dependencies only |
| `--fail-on <severity>` | none | `validate_report.py` exits 2 when a finding is at or above this level (for CI) |
| `--unmaintained-months <n>` | `24` | Months without a release before a library counts as unmaintained |

Outputs, in `--out`:

- `dependency-report.json`: machine-readable, validated against
  [`schema/report.schema.json`](dependency-audit/schema/report.schema.json).
- `dependency-report.html`: a self-contained page for people, rendered from the JSON.
- `raw/`: the evidence behind every finding (inventory, OSV records, scanner output, triage), and
  `raw/scan-input/`, the copy of the manifests and lockfiles the scanners read.

To re-render a report's HTML by hand (writes `dependency-report.html` next to the JSON, replacing it):

```
python dependency-audit/scripts/render_html.py dependency-audit-out/dependency-report.json
```

## Repository layout

```
dependency-audit/              the skill
├── SKILL.md                   agent instructions: workflow and hard rules
├── references/                setup procedure and triage.json format
├── rules/                     framework mapping, support sources, setup requirements (data)
├── schema/report.schema.json  report format
├── scripts/                   the workflow steps, plus setup_check.py, install_release.py and
│                              gradle_resolve.py (Gradle resolution, used by detect_inventory.py)
└── templates/                 HTML report template
dependency-audit-workspace/    skill evaluation
├── evals/evals.json           eval prompts and expected outcomes
└── fixtures/                  sample projects (Node, .NET, Java, Go/Python/pnpm monorepo)
samples/                       example JSON and HTML reports
SKILL_DESIGN.md                design spec, edge cases and open questions
```

Eval run outputs (`dependency-audit-workspace/iteration-*/`) are generated and git-ignored.

## Further reading

- [`SKILL_DESIGN.md`](SKILL_DESIGN.md): the full design spec.
- [`dependency-audit/references/setup.md`](dependency-audit/references/setup.md): setup statuses and rules.
- [`dependency-audit/references/triage.md`](dependency-audit/references/triage.md): how findings are triaged.
