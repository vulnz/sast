#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
post_edit_check.py — Lightweight Claude Code PostToolUse hook for the `sast` plugin.

Runs after `Write` or `Edit` tool calls:
  1. Performs an instant (<25ms) check on the modified file for high-confidence
     hardcoded credentials or private keys so accidental secret leaks are flagged
     immediately during coding.
  2. When `SAST_SCAN_ON_EDIT=1` is set in the environment, runs a single-file
     incremental scan using the `sast` library (`--files-from`).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# High-confidence secret patterns for instant in-session feedback
_SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-api03-[A-Za-z0-9\-_]{40,}\b")),
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj|live)-[A-Za-z0-9\-_]{32,}\b")),
    ("GitHub Personal Access Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub Fine-Grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
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
                    token = match.group(0)
                    # Ignore obvious sequential placeholders
                    if "123456" in token or "ABCDEF" in token or "xxxxxx" in token.lower():
                        continue
                    line_no = content.count("\n", 0, match.start()) + 1
                    alerts.append(f"  - {file_path.name}:{line_no}: Potential {label} detected")
            if alerts:
                sys.stderr.write(
                    "[sast] Warning — potential hardcoded secret(s) detected in edited file:\n"
                    + "\n".join(alerts[:5])
                    + "\nRun `/sast:secrets` to validate and inspect.\n"
                )
    except Exception:
        pass

    # 2. Optional full single-file SAST pass when SAST_SCAN_ON_EDIT=1
    if os.environ.get("SAST_SCAN_ON_EDIT") == "1":
        runner = Path(__file__).resolve().parent / "sast_runner.py"
        if runner.is_file():
            try:
                with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as tmp:
                    tmp.write(str(file_path) + "\n")
                    list_file = tmp.name
                try:
                    subprocess.run(
                        [
                            sys.executable,
                            str(runner),
                            str(file_path.parent),
                            "--files-from",
                            list_file,
                            "--no-sca",
                            "--no-report",
                            "--quiet",
                            "--no-banner",
                        ],
                        timeout=30,
                        check=False,
                    )
                finally:
                    try:
                        os.unlink(list_file)
                    except OSError:
                        pass
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
