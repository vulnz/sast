---
name: scan
description: Run Static Application Security Testing (SAST), cross-file AST taint analysis (16+ languages), secret detection with live key validation, SCA dependency CVE checks, IaC misconfiguration scanning, and CMS/web-shell detection using the bundled Insomnia SAST runner. Use when the user asks to scan a repository, directory, or file for security vulnerabilities.
argument-hint: "[path] [options]"
---

# SAST Full Security Scan (`/insomnia-sast:scan`)

Run a comprehensive static application security scan using the bundled Insomnia SAST plugin runner (`${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py`).

## Capabilities
- **Code Vulnerabilities (AST + Taint)**: Native AST and intra-/cross-file taint tracking across 16+ languages (Python, JS, TS, Java, Go, Ruby, PHP, C, C++, C#, Rust, Kotlin, Scala, Swift, Lua, Shell) + regex rules across 40+ languages (1,750+ FP-validated rules).
- **Secrets & API Keys**: 230+ vendor secret rules + entropy analysis with live provider key validation (`VALIDATED` / `invalid` / `not validated`).
- **Software Composition Analysis (SCA)**: OSV advisory matching across npm, PyPI, Maven, Go, Composer, Cargo, NuGet, RubyGems + dependency-confusion checks + vulnerable JS libraries (RetireJS-style) + ~24,000 CMS plugin/theme/core advisories.
- **Infrastructure-as-Code (IaC)**: Terraform, Kubernetes, Dockerfile, CloudFormation, Helm, and GitHub Actions security checks.
- **Web Shells & Malware**: Obfuscated backdoors, reverse shells, and double-extension upload detection.

## How to Run the Scan

Run the bundled runner script shipped inside the plugin, which executes the scan and prints a structured Markdown summary of the JSON report:

```bash
# Standard scan of target directory (defaults to current working directory)
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --claude-summary

# Output SARIF + JSON and gate on high/critical findings (exit code 2 on match)
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . -f json,sarif -o ./sast-reports --fail-on high --claude-summary

# Fast parallel scan or tripwire pre-pass for large monorepos
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . --fast --claude-summary

# Include test/ and fixtures/ directories (skipped by default to prevent false positives)
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . --scan-tests --claude-summary
```

## Reporting Instructions for Claude
1. Run the scan on the target path (default to `.` if no target was specified).
2. Read the structured summary and inspect the generated JSON report for full `code_context`, `source` → `sink` taint traces, and CWE metadata.
3. Group findings by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
4. For every finding reported to the user, provide:
   - Clickable file and line reference (`path/to/file.ext:line`)
   - Vulnerability class & CWE identifier
   - Dataflow explanation (taint source → sink) or secret validation status
   - Concrete, minimal remediation guidance (or offer to run `/insomnia-sast:fix`).
