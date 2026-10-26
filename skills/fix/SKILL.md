---
name: fix
description: Remediate vulnerabilities detected by the bundled Insomnia SAST runner (`--remediation`), apply minimal non-breaking security patches, and re-run the scanner to verify the fix eliminates the finding. Use when asked to fix, patch, or remediate SAST findings.
argument-hint: "[path-or-finding] [options]"
---

# SAST Vulnerability Remediation & Verification (`/insomnia-sast:fix`)

Fix security vulnerabilities identified by the bundled Insomnia SAST runner with minimal, surgical code changes and prove the fix works by re-scanning.

## Workflow

### Step 1: Identify or Generate Remediation Plan
If a recent SAST scan has not yet been run, scan the target using the bundled runner script:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --changed --claude-summary
```

Or generate advisory unified diffs directly (when `user_config.provider_api_key` is configured via `/plugin` options):

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --remediation --claude-summary
```

### Step 2: Apply Safe, Idiomatic Fixes by Vulnerability Class
- **SQL Injection (CWE-89)**: Replace string interpolation/concatenation with parameterized queries / prepared statements (`cursor.execute(sql, (param,))`, `$stmt->prepare()`, `$1` placeholders).
- **Command Injection (CWE-78)**: Replace shell execution (`os.system`, `subprocess.run(..., shell=True)`, `exec`, `sh -c`) with argument-array execution (`shell=False`) and strict input allowlisting.
- **Cross-Site Scripting / XSS (CWE-79)**: Apply context-appropriate output encoding, replace `innerHTML` / `dangerouslySetInnerHTML` with `textContent` or sanitized DOM APIs.
- **Path Traversal / LFI (CWE-22)**: Resolve canonical paths (`Path.resolve()`) and verify containment within the intended base directory (`commonpath` check).
- **Unsafe Deserialization / XXE (CWE-502 / CWE-611)**: Use `yaml.safe_load`, `defusedxml`, or disable external entities (`resolve_entities=False`).
- **Hardcoded Secrets (CWE-798)**: Move credentials to a dedicated secret store or configuration provider and provide a `.env.example` placeholder.

### Step 3: Mandatory Post-Fix Verification
Always re-run the bundled `sast_runner.py` script on the modified files to confirm the finding is resolved and no new issues were introduced:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . --changed --claude-summary
```

Never claim a vulnerability is fixed until the scan reports 0 findings for that location.
