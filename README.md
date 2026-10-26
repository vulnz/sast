# `sast` — Claude Code Plugin (SAST)

A self-contained Claude Code plugin (`sast`) that brings **SAST** directly into Claude Code via slash-command skills, subagents, and lifecycle hooks.

## Plugin Structure

```text
sast/
├── .claude-plugin/
│   ├── plugin.json                  # Plugin manifest (name: "sast")
│   ├── marketplace.json             # Marketplace manifest (name: "sast")
│   └── icon.png                     # 1024x1024 square PNG plugin icon
├── skills/
│   ├── scan/
│   │   └── SKILL.md                 # /sast:scan    — Full SAST + taint + secrets + IaC + SCA scan
│   ├── diff/
│   │   └── SKILL.md                 # /sast:diff    — Fast incremental scan on git changed files
│   ├── secrets/
│   │   └── SKILL.md                 # /sast:secrets — Secret detection + live key validation + git history
│   ├── sca/
│   │   └── SKILL.md                 # /sast:sca     — Dependency CVEs (OSV), dep confusion, CMS, licenses
│   ├── triage/
│   │   └── SKILL.md                 # /sast:triage  — Threat model, FP gate inspection & exploitability triage
│   └── fix/
│       └── SKILL.md                 # /sast:fix     — Auto-remediation diffs & post-patch verification
├── agents/
│   ├── security-auditor.md          # @agent-sast:security-auditor
│   └── remediation-engineer.md      # @agent-sast:remediation-engineer
├── hooks/
│   └── hooks.json                   # PostToolUse (Write|Edit) secret tripwire & optional single-file scan
├── scripts/
│   ├── sast_runner.py               # Bundled self-contained SAST runner & Claude summary formatter
│   └── post_edit_check.py           # Fast PostToolUse hook handler
└── README.md
```

## Quick Start

### Install from GitHub Marketplace (Recommended)
```bash
claude plugin marketplace add vulnz/sast
claude plugin install sast@sast
```

Or inside an interactive Claude Code session:
```text
/plugin marketplace add vulnz/sast
/plugin install sast@sast
```

### Validate the Plugin Locally
```bash
claude plugin validate .
```

## Slash Commands (Skills)

| Command | Description |
| :--- | :--- |
| `/sast:scan [path]` | Full SAST + AST/taint (16+ languages) + secrets + IaC + SCA scan |
| `/sast:diff [path]` | Fast incremental SAST scan of git modified, staged, and untracked files (`--changed`) |
| `/sast:secrets [path]` | Scan working tree and `--git-history` for hardcoded credentials with live provider key validation |
| `/sast:sca [path]` | Audit dependencies (OSV CVEs), dependency confusion, bundled JS libs, CMS plugins, and `--licenses` |
| `/sast:triage [path]` | Build STRIDE `--threat-model` and triage findings against the 0-FP real-only gate |
| `/sast:fix [path]` | Remediate vulnerabilities (`--remediation`) and re-verify with `--changed` |

## Subagents

- **`@agent-sast:security-auditor`** — Runs the bundled SAST scanner, traces source-to-sink dataflows in source files, and produces prioritized vulnerability reports.
- **`@agent-sast:remediation-engineer`** — Crafts minimal security patches and re-runs the scanner to verify each fix.

## Plugin Options (`userConfig`)

Configured through Claude Code's plugin configuration dialog (`/plugin` → Configure options):

- `scan_on_edit` (`boolean`, default `false`) — Enable automatic single-file SAST scanning inside the `PostToolUse` (`Write|Edit`) hook.
- `provider_api_key` (`string`, `sensitive: true`, optional) — Optional API key stored in Claude Code's secure credential storage for standalone AI triage/remediation diffs.
