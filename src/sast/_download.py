"""OS detection, manifest fetch, binary download + checksum + cache.

Pure stdlib (urllib/hashlib/platform) so the wheel has zero runtime deps and
stays a few KB. The hosted layout this expects on insom.ai:

    https://insom.ai/static/downloads/sast/manifest.json

    {
      "version": "2026.06.04-abc1234",
      "platforms": {
        "linux":   {"url": ".../sast-linux-x64",       "sha256": "<hex>"},
        "macos":   {"url": ".../sast-macos-x64",        "sha256": "<hex>"},
        "windows": {"url": ".../sast-windows-x64.exe",  "sha256": "<hex>"}
      }
    }

`url` may be absolute or relative to the manifest's own URL. `sha256` is
optional but strongly recommended — when present it is enforced.
"""

from __future__ import annotations

import hashlib
import os
import platform
import stat
import sys
import urllib.request
from urllib.parse import urljoin

# Override with the SAST_MANIFEST_URL env var (handy for staging / self-hosting).
DEFAULT_MANIFEST_URL = "https://insom.ai/static/downloads/sast/manifest.json"

_USER_AGENT = "sast-launcher"


class DownloadError(RuntimeError):
    """Raised when the binary cannot be fetched or verified."""


def manifest_url() -> str:
    return os.environ.get("SAST_MANIFEST_URL", DEFAULT_MANIFEST_URL).strip()


def detect_platform() -> str:
    """Map the host OS to a manifest platform key (linux / macos / windows)."""
    system = platform.system().lower()
    if system.startswith("linux"):
        return "linux"
    if system == "darwin":
        return "macos"
    if system.startswith("win"):
        return "windows"
    raise DownloadError(
        f"Unsupported operating system: {platform.system()!r}. "
        "sast ships binaries for Linux, macOS and Windows only."
    )


def _arch_is_supported() -> bool:
    """The hosted binaries are x86-64 only (for now). arm64 macs run via Rosetta."""
    machine = platform.machine().lower()
    return machine in {"x86_64", "amd64", "x64"} or platform.system().lower() == "darwin"


def cache_dir() -> str:
    """Per-user cache directory for the downloaded binary, by OS convention."""
    override = os.environ.get("SAST_CACHE_DIR")
    if override:
        return override
    system = platform.system().lower()
    if system.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        return os.path.join(base, "sast", "bin")
    if system == "darwin":
        return os.path.expanduser("~/Library/Application Support/sast/bin")
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "sast", "bin")


def binary_path() -> str:
    name = "sast.exe" if detect_platform() == "windows" else "sast"
    return os.path.join(cache_dir(), name)


def _version_marker() -> str:
    return os.path.join(cache_dir(), ".version")


def _lastcheck_marker() -> str:
    return os.path.join(cache_dir(), ".lastcheck")


def _update_interval() -> int:
    """Seconds between background 'is a newer engine available?' checks.

    Default 24h. Set SAST_UPDATE_INTERVAL=0 to disable auto-update entirely
    (the cached binary is then used until `sast self-update` is run).
    """
    raw = os.environ.get("SAST_UPDATE_INTERVAL", "").strip()
    if not raw:
        return 86400
    try:
        return max(0, int(raw))
    except ValueError:
        return 86400


def _update_check_due() -> bool:
    interval = _update_interval()
    if interval <= 0:
        return False
    import time

    try:
        last = os.path.getmtime(_lastcheck_marker())
    except OSError:
        return True  # never checked
    return (time.time() - last) >= interval


def _mark_checked() -> None:
    try:
        os.makedirs(cache_dir(), exist_ok=True)
        with open(_lastcheck_marker(), "w", encoding="utf-8") as fh:
            fh.write("")
    except OSError:
        pass


def _http_get(url: str, *, binary: bool) -> bytes:
    import ssl

    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (https only by default)
            return resp.read()
    except ssl.SSLCertVerificationError as exc:
        hint = ""
        if platform.system().lower() == "darwin":
            # Classic python.org-build issue: the bundled OpenSSL has no CA store
            # until the user runs the post-install "Install Certificates.command".
            hint = (
                "\nOn macOS this usually means your Python install has no CA "
                "certificates. Run:\n"
                '  /Applications/Python\\ 3.x/Install\\ Certificates.command\n'
                "or:  pip install --upgrade certifi"
            )
        raise DownloadError(f"TLS certificate verification failed for {url}: {exc}{hint}") from exc
    except Exception as exc:  # urllib raises a zoo of exception types
        raise DownloadError(f"Could not fetch {url}: {exc}") from exc


def _load_manifest() -> dict:
    import json

    raw = _http_get(manifest_url(), binary=False)
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise DownloadError(f"Manifest at {manifest_url()} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "platforms" not in data:
        raise DownloadError("Manifest is missing the required 'platforms' object.")
    return data


def _verify_sha256(blob: bytes, expected: str) -> None:
    actual = hashlib.sha256(blob).hexdigest()
    if actual.lower() != expected.lower():
        raise DownloadError(
            "Checksum mismatch — refusing to install a tampered or corrupt binary.\n"
            f"  expected sha256: {expected}\n"
            f"  actual   sha256: {actual}"
        )


def current_version() -> str | None:
    try:
        with open(_version_marker(), encoding="utf-8") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def ensure_binary(*, force: bool = False, quiet: bool = False) -> str:
    """Return the path to the cached binary, downloading it if needed.

    Behaviour:
      * missing binary  -> download it (first run).
      * force=True      -> always re-fetch the latest (used by `sast self-update`).
      * binary present  -> reused immediately. At most once per
        SAST_UPDATE_INTERVAL (default 24h) it also checks insom.ai for a newer
        version and upgrades automatically. Network failures fail open: the
        cached binary keeps working offline.
    """
    path = binary_path()
    exists = os.path.exists(path)

    manifest = None
    if exists and not force:
        if not _update_check_due():
            return path
        # An update check is due — see whether insom.ai has a newer build.
        try:
            manifest = _load_manifest()
        except DownloadError:
            _mark_checked()  # offline / server down: keep using the cached binary
            return path
        _mark_checked()
        latest = manifest.get("version") or ""
        if latest == (current_version() or ""):
            return path  # already on the latest
        _warn(quiet, f"sast: newer engine available ({latest}); updating...")

    if not _arch_is_supported():
        _warn(
            quiet,
            f"warning: CPU architecture {platform.machine()!r} has no native sast build; "
            "attempting the x86-64 binary.",
        )

    plat = detect_platform()
    if manifest is None:
        _warn(quiet, "sast: fetching the SAST engine (first run)..." if not force
              else "sast: updating the SAST engine...")
        manifest = _load_manifest()

    entry = manifest.get("platforms", {}).get(plat)
    if not entry or not entry.get("url"):
        raise DownloadError(f"Manifest has no download entry for platform {plat!r}.")

    url = urljoin(manifest_url(), entry["url"])
    blob = _http_get(url, binary=True)

    sha = entry.get("sha256")
    if sha:
        _verify_sha256(blob, sha)
    else:
        _warn(quiet, "warning: manifest provided no sha256 — skipping integrity check.")

    os.makedirs(cache_dir(), exist_ok=True)
    tmp = path + ".part"
    with open(tmp, "wb") as fh:
        fh.write(blob)
    if plat != "windows":
        mode = os.stat(tmp).st_mode
        os.chmod(tmp, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    os.replace(tmp, path)

    version = manifest.get("version", "")
    try:
        with open(_version_marker(), "w", encoding="utf-8") as fh:
            fh.write(version)
    except OSError:
        pass
    _mark_checked()

    _warn(quiet, f"sast: installed engine {version or '(unversioned)'} -> {path}")
    return path


def _warn(quiet: bool, msg: str) -> None:
    if not quiet:
        print(msg, file=sys.stderr)
