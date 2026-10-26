---
name: fix
description: Remediate vulnerabilities detected by our `sast` library (`--remediation`), apply minimal non-breaking security patches, and re-run `sast` to verify the fix eliminates the finding. Use when asked to fix, patch, or remediate SAST findings.
argument-hint: "[path-or-finding] [options]"
---

# SAST Vulnerability Remediation & Verification (`/sast:fix`)

Fix security vulnerabilities identified by our `sast` library with minimal, surgical code changes and prove the fix works by re-scanning.

## Workflow

### Step 1: Identify or Generate Remediation Plan
If a recent SAST scan has not yet been run, scan the target (or generate AI advisory diffs with `--remediation`):

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --changed --claude-summary
```

Or to generate advisory unified diffs directly from the `sast` engine (when `sast config ai` or `ANTHROPIC_API_KEY` is configured):

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --remediation --claude-summary
```

### Step 2: Apply Safe, Idiomatic Fixes by Vulnerability Class
- **SQL Injection (CWE-89)**: Replace string interpolation/concatenation with parameterized queries / prepared statements (`cursor.execute(sql, (param,))`, `$stmt->prepare()`, `$1` placeholders).
- **Command Injection (CWE-78)**: Replace shell execution (`os.system`, `subprocess.run(..., shell=True)`, `exec`, `sh -c`) with argument-array execution (`shell=False`) and strict input allowlisting.
- **Cross-Site Scripting / XSS (CWE-79)**: Apply context-appropriate output encoding, replace `innerHTML` / `dangerouslySetInnerHTML` with `textContent` or sanitized DOM APIs.
- **Path Traversal / LFI (CWE-22)**: Resolve canonical paths (`os.path.realpath` / `Path.resolve()`) and verify containment within the intended base directory (`commonpath` check).
- **Unsafe Deserialization / XXE (CWE-502 / CWE-611)**: Use `yaml.safe_load`, `defusedxml`, or disable external entities (`resolve_entities=False`).
- **Hardcoded Secrets (CWE-798)**: Read credentials from `os.environ` / secret stores and provide a `.env.example` placeholder.

### Step 3: Mandatory Post-Fix Verification
Always re-run `sast` on the modified files to confirm the finding is resolved and no new issues were introduced:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . --changed --claude-summary
```

Never claim a vulnerability is fixed until `sast` reports 0 findings for that location.
