---
name: scan
description: Run Static Application Security Testing (SAST), cross-file AST taint analysis (16+ languages), secret detection with live key validation, SCA dependency CVE checks, IaC misconfiguration scanning, and CMS/web-shell detection using our `sast` library. Use when the user asks to scan a repository, directory, file, or remote Git URL for security vulnerabilities.
argument-hint: "[path-or-repo-url] [options]"
---

# SAST Full Security Scan (`/sast:scan`)

Run a comprehensive static application security scan using our `sast` library (`pip install sast` / `sast` CLI / `core.sast_engine`).

## Capabilities of Our `sast` Library
- **Code Vulnerabilities (AST + Taint)**: Native tree-sitter AST & intra-/cross-file taint tracking across 16+ languages (Python, JS, TS, Java, Go, Ruby, PHP, C, C++, C#, Rust, Kotlin, Scala, Swift, Lua, Shell) + regex rules across 40+ languages (1,750+ FP-validated rules).
- **Secrets & API Keys**: 230+ vendor secret rules + entropy analysis with live provider key validation (`VALIDATED` / `invalid` / `not validated`).
- **Software Composition Analysis (SCA)**: OSV advisory matching across npm, PyPI, Maven, Go, Composer, Cargo, NuGet, RubyGems + dependency-confusion checks + vulnerable JS libraries (RetireJS-style) + ~24,000 CMS plugin/theme/core advisories.
- **Infrastructure-as-Code (IaC)**: Terraform, Kubernetes, Dockerfile, CloudFormation, Helm, and GitHub Actions security checks.
- **Web Shells & Malware**: Obfuscated backdoors, reverse shells, and double-extension upload detection.

## How to Run the Scan

### 1. Via the Plugin Runner Script (Recommended)
Run our bundled runner script, which automatically locates `sast` (or `core.sast_engine`), bootstraps `pip install sast` if needed, and prints a structured Markdown summary of the JSON report:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --claude-summary
```

### 2. Direct CLI Invocation (`sast`)
You can also invoke `sast` (or `python -m sast`) directly with any engine flags:

```bash
# Standard scan of current directory (writes HTML, TXT, JSON reports to ./reports)
sast . --no-banner

# Output SARIF + JSON and gate on high/critical findings (exit code 2 on match)
sast . -f json,sarif -o ./sast-reports --fail-on high --no-banner

# Fast parallel scan or tripwire pre-pass for huge monorepos
sast . --fast --no-banner
sast . --tripwire --no-banner

# Scan a remote repository URL directly (shallow-cloned and cleaned up automatically)
sast https://github.com/owner/repo --no-banner

# Include test/ and fixtures/ directories (skipped by default to prevent false positives)
sast . --scan-tests --no-banner
```

### 3. Direct Python Library API (`core.sast_engine`)
When running inside the Insomnia/Dominator monorepo, you can also call the Python library directly:

```python
from core.sast_engine import run_sast_analysis, write_reports, findings_to_sarif

result = run_sast_analysis(".", real_only=True, run_sca=True, deep_analysis=True)
print(f"Actionable findings: {len(result.findings)} (raw: {len(result.raw_findings)})")
for f in result.findings:
    print(f"[{f.get('severity', 'INFO').upper()}] {f.get('file')}:{f.get('line_number')} - {f.get('name')} ({f.get('cwe')})")
```

## Reporting Instructions for Claude
1. Run the scan on the target path or URL (default to `.` if no target was specified).
2. Read the structured summary and inspect the generated JSON report for full `code_context`, `source` → `sink` taint traces, and CWE metadata.
3. Group findings by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
4. For every finding reported to the user, provide:
   - Clickable file and line reference (`path/to/file.ext:line`)
   - Vulnerability class & CWE identifier
   - Dataflow explanation (taint source → sink) or secret validation status
   - Concrete, minimal remediation guidance (or offer to run `/sast:fix`).
