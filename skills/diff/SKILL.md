---
name: diff
description: Run a fast incremental SAST security scan on git changed, staged, and untracked files using the bundled SAST runner (`--changed`). Use before committing, pushing, or opening a pull request, or when reviewing recent code edits for security regressions.
argument-hint: "[path] [extra-flags]"
---

# SAST Incremental Diff Scan (`/sast:diff`)

Scan only the files modified, staged, or untracked relative to `git HEAD` using the bundled `sast_runner.py` script in `--changed` mode.

## Workflow

1. **Check git working tree status**:
   Verify changed files with `git status --short`.
2. **Run incremental SAST scan**:
   Execute the bundled plugin runner in `--changed` mode:
   ```bash
   python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --changed --claude-summary
   ```
3. **Review and correlate with the diff**:
   - Cross-reference each finding with `git diff` to distinguish newly introduced vulnerabilities from pre-existing lines in touched files.
   - Highlight any `CRITICAL` or `HIGH` severity findings and any newly introduced hardcoded secrets.
   - Propose concrete inline fixes before the code is committed or pushed.
