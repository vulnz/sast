"""`sast` entry point: ensure the engine binary is present, then hand off to it.

All arguments after `sast` are passed straight through to the underlying SAST
binary, so `sast --help`, `sast <path> --sarif`, etc. behave exactly like the
native CLI. A few launcher-only subcommands are intercepted first.
"""

from __future__ import annotations

import errno
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

_LAUNCHER_HELP = f"""sast {__version__} — launcher for the Insomnia SAST engine

Usage:
  sast [SAST-ARGS...]     Run the SAST engine (downloads it on first use).
  sast self-update        Re-download the latest engine binary.
  sast self-version       Show launcher + cached-engine versions.
  sast self-where         Print the path to the cached engine binary.

Everything else is forwarded to the engine. Try:  sast --help
"""


def _exec(path: str, args: list[str]) -> int:
    # On POSIX, exec replaces this process so signals/exit codes pass through
    # cleanly. On Windows there is no exec, so spawn and forward the exit code.
    if os.name == "posix":
        os.execv(path, [path, *args])  # never returns on success
    completed = subprocess.run([path, *args])
    return completed.returncode


def _is_arch_error(exc: OSError) -> bool:
    # macOS "Bad CPU type in executable" (EBADARCH = 86) or a generic exec
    # format error — i.e. the cached binary is the wrong architecture.
    return exc.errno in {getattr(errno, "EBADARCH", 86), 86, errno.ENOEXEC} or (
        "CPU type" in str(exc)
    )


def _run_engine(args: list[str]) -> int:
    path = ensure_binary()
    try:
        return _exec(path, args)
    except OSError as exc:
        # A wrong-architecture cached binary (e.g. an x86_64 build left by an
        # older launcher on an Apple Silicon Mac). Re-fetch the correct binary
        # once and retry, rather than failing with a raw OSError.
        if _is_arch_error(exc):
            print(
                "sast: cached engine is the wrong CPU architecture; re-downloading...",
                file=sys.stderr,
            )
            path = ensure_binary(force=True)
            return _exec(path, args)
        raise


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv:
        cmd = argv[0]
        if cmd == "self-update":
            ensure_binary(force=True)
            return 0
        if cmd == "self-version":
            print(f"sast launcher {__version__}")
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
        print(f"sast: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
