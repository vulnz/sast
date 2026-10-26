---
name: secrets
description: Scan source code and git commit history for hardcoded secrets, API keys, tokens, and private keys with live provider validation using the bundled Insomnia SAST runner (`--secrets-only` and `--git-history`). Use when auditing for leaked credentials or checking before a release/push.
argument-hint: "[path] [--git-history] [--noapivalidate]"
---

# SAST Secret & Credential Scanner (`/insomnia-sast:secrets`)

Scan a codebase and its git commit history across 230+ vendor secret rule packs and entropy detectors using the bundled `sast_runner.py` script, with optional live API key validation against providers.

## Commands

### 1. Fast Working-Tree Secret Scan (with Live Validation)
By default, the scanner tests detected keys against their provider APIs and labels each secret `VALIDATED` (with proof), `invalid`, or `not validated`:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --secrets-only --claude-summary
```

### 2. Offline Secret Scan (No Outbound Provider Calls)
Pass `--noapivalidate` to disable live provider checks in air-gapped or strict environments:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . --secrets-only --noapivalidate --claude-summary
```

### 3. Git Commit History Scan (TruffleHog-Style)
Scan historical commits for credentials that were committed and later deleted from the working tree (bounded by `--git-history-commits`, default 1000, and a 60-second safety cap):

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . --secrets-only --git-history --git-history-commits 1000 --claude-summary
```

## Reporting Guidelines
- Never echo full live secret values back in plain text; redact the middle characters (e.g., `sk-...9f2a`).
- Clearly highlight any finding marked **`VALIDATED`** as an active credential leak requiring immediate rotation/revocation in addition to code removal.
- Provide remediation steps: move secrets to a dedicated secret manager or configuration store, add patterns to `.gitignore`, and purge git history (`git filter-repo` / BFG) if leaked in commits.
