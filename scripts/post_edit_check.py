#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
post_edit_check.py — Lightweight Claude Code PostToolUse hook for the `sast` plugin.

Runs after `Write` or `Edit` tool calls:
  1. Performs an instant (<25ms) check on the modified file for high-confidence
     hardcoded credentials or private keys so accidental secret leaks are flagged
     immediately during coding.
  2. When `--scan-on-edit true` is passed (via `userConfig.scan_on_edit`), runs a
     single-file incremental scan using the bundled `sast_runner.py` script.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# High-confidence secret patterns for instant in-session feedback
_SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("API Key Prefix", re.compile(r"\bsk-(?:ant|proj|live)-[A-Za-z0-9\-_]{32,}\b")),
    ("SCM Personal Access Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Fine-Grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Workspace Bot Token", re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b")),
    ("Cloud API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Payment Live Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]

_SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", "fixtures", "tests", "test"}


def _is_test_or_detector_file(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if parts & _SKIP_DIRS:
        return True
    name = path.name.lower()
    if name.startswith("test_") or name.endswith("_test.py") or "detector" in name or "pattern" in name:
        return True
    return False


def _scan_on_edit_enabled(argv: list[str]) -> bool:
    for idx, arg in enumerate(argv):
        if arg == "--scan-on-edit" and idx + 1 < len(argv):
            return argv[idx + 1].strip().lower() in ("1", "true", "yes")
        if arg.startswith("--scan-on-edit="):
            return arg.split("=", 1)[1].strip().lower() in ("1", "true", "yes")
    return False


def main() -> int:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0
        payload = json.loads(raw)
    except Exception:
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path_str = tool_input.get("file_path") or tool_input.get("path")
    if not file_path_str:
        return 0

    file_path = Path(file_path_str)
    if not file_path.is_file() or _is_test_or_detector_file(file_path):
        return 0

    # 1. Fast secret tripwire (<25ms)
    try:
        if file_path.stat().st_size <= 2 * 1024 * 1024:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            alerts = []
            for label, pat in _SECRET_PATTERNS:
                for match in pat.finditer(content):
                    candidate = match.group(0)
                    if "123456" in candidate or "ABCDEF" in candidate or "xxxxxx" in candidate.lower():
                        continue
                    line_no = content.count("\n", 0, match.start()) + 1
                    alerts.append(f"  - {file_path.name}:{line_no}: Potential {label} detected")
            if alerts:
                sys.stderr.write(
                    "[sast] Warning — potential hardcoded credential(s) detected in edited file:\n"
                    + "\n".join(alerts[:5])
                    + "\nRun `/sast:secrets` to inspect and remediate.\n"
                )
    except Exception:
        pass

    # 2. Optional single-file SAST pass when userConfig.scan_on_edit is enabled
    if _scan_on_edit_enabled(sys.argv[1:]):
        runner = Path(__file__).resolve().parent / "sast_runner.py"
        if runner.is_file():
            try:
                with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as tmp:
                    tmp.write(str(file_path) + "\n")
                    list_file = Path(tmp.name)
                try:
                    subprocess.run(
                        [
                            sys.executable,
                            str(runner),
                            str(file_path.parent),
                            "--files-from",
                            str(list_file),
                            "--no-sca",
                            "--no-report",
                            "--quiet",
                            "--no-banner",
                        ],
                        timeout=30,
                        check=False,
                    )
                finally:
                    list_file.unlink(missing_ok=True)
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
