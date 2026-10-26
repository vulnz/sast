---
name: triage
description: Perform deep vulnerability triage, STRIDE threat modeling, source-to-sink reachability verification, and false-positive filtering using our `sast` library (`--threat-model`, `--ai-validate`, `--ai-triage`, and `core.sast_filters`). Use when evaluating whether SAST findings are exploitable or false positives.
argument-hint: "[path] [--all-findings] [--threat-model]"
---

# SAST Triage & Threat Modeling (`/sast:triage`)

Validate SAST findings, construct a STRIDE threat model of the repository, and separate true exploitable vulnerabilities from false positives using our `sast` engine's 4-gate real-only filter and AI triage pipeline.

## Workflow

### 1. Generate Threat Model & Triage Report
Run `sast` with `--threat-model` (plus `--ai-validate --ai-triage` when an AI provider is configured via `sast config ai` or `ANTHROPIC_API_KEY`):

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --threat-model --claude-summary
```

To inspect both filtered (`findings`) and unfiltered (`raw_findings`) candidates for forensic comparison:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . --all-findings --threat-model --claude-summary
```

### 2. Programmatic False-Positive Filter Inspection (`core.sast_filters`)
When working inside the Insomnia/Dominator codebase, you can directly test why a candidate finding is accepted or rejected by the 0-FP gate:

```python
from core.sast_engine import run_sast_analysis
from core.sast_filters import is_real_finding

res = run_sast_analysis(".", real_only=False)
for f in res.raw_findings:
    verdict = is_real_finding(f)
    print(f"{f.get('file')}:{f.get('line_number')} [{f.get('name')}] -> real={verdict}")
```

### 3. Manual Claude Verification Checklist
For each finding under review, verify:
1. **Source**: Does attacker-controlled input (`$_GET`, `req.body`, `request.args`, CLI/env/header/file input, DOM `location.search`) enter the flow?
2. **Sanitization / Parameterization**: Is the value cast to an integer, bound via parameterized query (`?` / `$1`), allowlisted, or context-encoded before reaching the sink?
3. **Sink**: Does the tainted value reach a dangerous execution, query, deserialization, path, or rendering sink?
4. **Verdict**: Classify each finding as **Exploitable**, **Likely Exploitable**, **Defense-in-Depth**, or **False Positive** with exact code evidence.
