"""`ins` entry point: ensure the engine binary is present, then hand off to it.

All arguments after `ins` are passed straight through to the underlying SAST
binary, so `ins --help`, `ins <path> --sarif`, etc. behave exactly like the
native CLI. A few launcher-only subcommands are intercepted first.
"""

from __future__ import annotations

import os
import subprocess
import sys

from . import __version__
from ._download import (
    DownloadError,
    binary_path,
    current_version,
    ensure_binary,
)

_LAUNCHER_HELP = f"""ins {__version__} — launcher for the Insomnia SAST engine

Usage:
  ins [SAST-ARGS...]      Run the SAST engine (downloads it on first use).
  ins self-update         Re-download the latest engine binary.
  ins self-version        Show launcher + cached-engine versions.
  ins self-where          Print the path to the cached engine binary.

Everything else is forwarded to the engine. Try:  ins --help
"""


def _run_engine(args: list[str]) -> int:
    path = ensure_binary()
    # On POSIX, exec replaces this process so signals/exit codes pass through
    # cleanly. On Windows there is no exec, so spawn and forward the exit code.
    if os.name == "posix":
        os.execv(path, [path, *args])  # never returns
    completed = subprocess.run([path, *args])
    return completed.returncode


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv:
        cmd = argv[0]
        if cmd == "self-update":
            ensure_binary(force=True)
            return 0
        if cmd == "self-version":
            print(f"ins launcher {__version__}")
            print(f"engine        {current_version() or '(not yet installed)'}")
            return 0
        if cmd == "self-where":
            print(binary_path())
            return 0
        if cmd in ("self-help", "--launcher-help"):
            print(_LAUNCHER_HELP)
            return 0

    try:
        return _run_engine(argv)
    except DownloadError as exc:
        print(f"ins: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
