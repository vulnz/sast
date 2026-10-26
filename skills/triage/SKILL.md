---
name: triage
description: Perform deep vulnerability triage, STRIDE threat modeling, source-to-sink reachability verification, and false-positive filtering using the bundled SAST runner (`--threat-model`). Use when evaluating whether SAST findings are exploitable or false positives.
argument-hint: "[path] [--all-findings] [--threat-model]"
---

# SAST Triage & Threat Modeling (`/sast:triage`)

Validate SAST findings, construct a STRIDE threat model of the repository, and separate true exploitable vulnerabilities from false positives using the bundled `sast_runner.py` script.

## Workflow

### 1. Generate Threat Model & Triage Report
Run the bundled `sast_runner.py` script with `--threat-model` (and optional standalone AI triage if `user_config.provider_api_key` is configured in the plugin options):

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --threat-model --claude-summary
```

To inspect both filtered (`findings`) and unfiltered (`raw_findings`) candidates for forensic comparison:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . --all-findings --threat-model --claude-summary
```

### 2. Manual Claude Verification Checklist
For each finding under review, verify:
1. **Source**: Does attacker-controlled input (`$_GET`, `req.body`, `request.args`, CLI/header/file input, DOM `location.search`) enter the flow?
2. **Sanitization / Parameterization**: Is the value cast to an integer, bound via parameterized query (`?` / `$1`), allowlisted, or context-encoded before reaching the sink?
3. **Sink**: Does the tainted value reach a dangerous execution, query, deserialization, path, or rendering sink?
4. **Verdict**: Classify each finding as **Exploitable**, **Likely Exploitable**, **Defense-in-Depth**, or **False Positive** with exact code evidence.
