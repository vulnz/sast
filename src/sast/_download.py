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
# This is the manifest insom.ai already publishes; its `sast` section lists the
# latest per-OS engine build (filename + sha256 + version).
DEFAULT_MANIFEST_URL = "https://insom.ai/static/downloads/plugin_manifest.json"

_USER_AGENT = "sast-launcher"


class DownloadError(RuntimeError):
    """Raised when the binary cannot be fetched or verified."""


def manifest_url() -> str:
    return os.environ.get("SAST_MANIFEST_URL", DEFAULT_MANIFEST_URL).strip()


def detect_platform() -> str:
    """Map the host OS+arch to a manifest platform key
    (linux / linux-arm64 / macos / macos-arm64 / windows)."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system.startswith("linux"):
        if machine in {"aarch64", "arm64"}:
            return "linux-arm64"
        return "linux"
    if system == "darwin":
        # Apple Silicon -> native arm64 build. Intel (x86_64) -> the "macos" key,
        # which is the x86_64 binary that runs natively on Intel (and on Apple
        # Silicon via Rosetta). An arm64 binary will NOT run on an Intel Mac.
        if machine in {"arm64", "aarch64"}:
            return "macos-arm64"
        return "macos"
    if system.startswith("win"):
        return "windows"
    raise DownloadError(
        f"Unsupported operating system: {platform.system()!r}. "
        "sast ships binaries for Linux, macOS and Windows only."
    )


def _arch_is_supported() -> bool:
    """Which host CPUs have a native engine. x86-64 everywhere; arm64 macs run
    via Rosetta; linux arm64 (aarch64) now has a native build too."""
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64", "x64"}:
        return True
    if platform.system().lower() == "darwin":
        return True
    if platform.system().lower().startswith("linux") and machine in {"aarch64", "arm64"}:
        return True
    return False


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


def _ssl_context(*, insecure: bool = False):
    """Build a TLS context that actually has a CA store.

    macOS python.org / pyenv builds ship without a usable system CA store, so
    the stdlib default context raises CERTIFICATE_VERIFY_FAILED on the very
    first HTTPS call. We prefer certifi's Mozilla CA bundle (a declared
    dependency) and fall back to the stdlib default when it is unavailable.
    """
    import ssl

    if insecure:
        return ssl._create_unverified_context()
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _http_get(url: str, *, binary: bool) -> bytes:
    import ssl

    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    insecure = os.environ.get("SAST_INSECURE_TLS", "").strip().lower() in {"1", "true", "yes"}

    def _open(ctx) -> bytes:
        with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:  # noqa: S310 (https only)
            return resp.read()

    try:
        return _open(_ssl_context(insecure=insecure))
    except Exception as exc:  # urllib raises a zoo of exception types
        # urllib wraps the TLS error in URLError, so unwrap to find the cause.
        reason = getattr(exc, "reason", None)
        is_cert = isinstance(exc, ssl.SSLCertVerificationError) or isinstance(
            reason, ssl.SSLCertVerificationError
        )
        if is_cert and not insecure:
            # Retry once with certifi explicitly — covers a stale/empty system
            # CA store even if our primary context fell back to the default.
            try:
                import certifi

                return _open(ssl.create_default_context(cafile=certifi.where()))
            except Exception:
                pass
            hint = (
                "\nTLS certificate verification failed — your Python has no usable CA "
                "store (common on macOS python.org / pyenv builds). Fix with ONE of:\n"
                "  pip install --upgrade certifi\n"
                "  /Applications/Python\\ 3.x/Install\\ Certificates.command   (macOS)\n"
                "Or, on a trusted network only, set SAST_INSECURE_TLS=1 to skip "
                "verification."
            )
            raise DownloadError(f"Could not fetch {url}: {exc}{hint}") from exc
        raise DownloadError(f"Could not fetch {url}: {exc}") from exc


def _load_manifest() -> dict:
    import json

    raw = _http_get(manifest_url(), binary=False)
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise DownloadError(f"Manifest at {manifest_url()} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not (data.get("platforms") or data.get("sast")):
        raise DownloadError("Manifest has neither a 'sast' nor a 'platforms' section.")
    return data


def _plat_candidates(plat: str) -> list[str]:
    """Preferred manifest keys for `plat`, in priority order.

    Apple Silicon prefers the native arm64 build but can fall back to the
    Intel ("macos") binary via Rosetta if no arm64 build is published yet.
    """
    if plat == "macos-arm64":
        return ["macos-arm64", "macos"]
    return [plat]


def _resolve_entry(manifest: dict, plat: str, murl: str) -> dict:
    """Resolve a download entry for `plat`, trying architecture fallbacks."""
    last_err: DownloadError | None = None
    for cand in _plat_candidates(plat):
        try:
            return _resolve_one(manifest, cand, murl)
        except DownloadError as exc:
            last_err = exc
    raise last_err or DownloadError(f"Manifest has no download entry for platform {plat!r}.")


def _resolve_one(manifest: dict, plat: str, murl: str) -> dict:
    """Return {url, sha256, identity} for `plat`, handling both manifest shapes.

    * insom.ai `plugin_manifest.json`:  {"sast": {"<plat>": {filename, sha256, version, uploaded}}}
    * clean schema:                     {"version": ..., "platforms": {"<plat>": {url, sha256}}}
    """
    # Clean schema (url-based) takes precedence if present.
    plats = manifest.get("platforms")
    if isinstance(plats, dict) and isinstance(plats.get(plat), dict):
        e = plats[plat]
        if e.get("url"):
            return {
                "url": urljoin(murl, e["url"]),
                "sha256": e.get("sha256"),
                "identity": (e.get("version") or manifest.get("version") or ""),
            }

    # insom.ai plugin_manifest.json (filename-based).
    sast = manifest.get("sast")
    if isinstance(sast, dict):
        if plat in sast:
            e = sast[plat]
            if not e:
                raise DownloadError(
                    f"No {plat} SAST engine build is available on insom.ai yet."
                )
            fn = e.get("filename") or e.get("url")
            if not fn:
                raise DownloadError(f"Manifest entry for {plat} has no filename/url.")
            ident = f"{e.get('version', '')}|{e.get('uploaded', '')}"
            return {"url": urljoin(murl, fn), "sha256": e.get("sha256"), "identity": ident}

    raise DownloadError(f"Manifest has no download entry for platform {plat!r}.")


def _macho_arches(blob: bytes) -> set[str]:
    """CPU arch names inside a Mach-O blob ('x86_64', 'arm64', ...). Handles
    thin little-endian Mach-O (modern macOS) and fat/universal binaries. Returns
    an empty set when the blob isn't recognisably Mach-O (then we don't block)."""
    import struct

    if len(blob) < 8:
        return set()
    cpu = {0x01000007: "x86_64", 0x0100000C: "arm64", 7: "i386", 12: "arm"}
    be = struct.unpack(">I", blob[:4])[0]
    le = struct.unpack("<I", blob[:4])[0]
    if be in (0xCAFEBABE, 0xCAFEBABF):  # fat/universal — big-endian header
        out: set[str] = set()
        n = struct.unpack(">I", blob[4:8])[0]
        rec = 20 if be == 0xCAFEBABE else 32
        off = 8
        for _ in range(min(n, 32)):
            if off + 4 > len(blob):
                break
            out.add(cpu.get(struct.unpack(">I", blob[off:off + 4])[0], "unknown"))
            off += rec
        return out
    if le in (0xFEEDFACE, 0xFEEDFACF):  # thin Mach-O, little-endian
        return {cpu.get(struct.unpack("<I", blob[4:8])[0], "unknown")}
    return set()


def _verify_runnable_arch(blob: bytes, quiet: bool) -> None:
    """Refuse a macOS binary the host CPU cannot execute, BEFORE we cache/exec it.

    An arm64 Mach-O cannot run on an Intel Mac at all (Rosetta only runs x86 on
    Apple Silicon, not the reverse) — exec'ing it gives the cryptic
    `OSError: [Errno 86] Bad CPU type in executable`. We turn that into a clear,
    actionable message and avoid caching a binary that can never run.
    Apple Silicon can run BOTH arm64 (native) and x86_64 (Rosetta), so it never
    hard-fails here.
    """
    if platform.system().lower() != "darwin":
        return
    arches = _macho_arches(blob)
    if not arches:
        return  # not Mach-O / unrecognised — don't block
    host = platform.machine().lower()
    if host in {"x86_64", "amd64", "x64"} and "x86_64" not in arches:
        raise DownloadError(
            "The downloaded macOS engine is "
            + "/".join(sorted(arches))
            + ", but this is an Intel (x86_64) Mac, which cannot run it "
            "(errno 86 'Bad CPU type in executable').\n"
            "This is a server-side build issue — the macos-x64 download is currently "
            "serving the wrong architecture — not anything you can fix locally.\n"
            "Until the Intel build is republished, run sast on Apple Silicon, Linux or "
            "Windows, or build the engine from source (github.com/vulnz/sast)."
        )


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

    plat = detect_platform()
    manifest = None
    if exists and not force:
        if not _update_check_due():
            return path
        # An update check is due — see whether insom.ai has a newer build.
        try:
            manifest = _load_manifest()
            entry = _resolve_entry(manifest, plat, manifest_url())
        except DownloadError:
            _mark_checked()  # offline / server down / no build: keep cached binary
            return path
        _mark_checked()
        if entry["identity"] == (current_version() or ""):
            return path  # already on the latest
        _warn(quiet, f"sast: newer engine available ({entry['identity']}); updating...")

    if not _arch_is_supported():
        _warn(
            quiet,
            f"warning: CPU architecture {platform.machine()!r} has no native sast build; "
            "attempting the x86-64 binary.",
        )

    if manifest is None:
        _warn(quiet, "sast: fetching the SAST engine (first run)..." if not force
              else "sast: updating the SAST engine...")
        manifest = _load_manifest()
        entry = _resolve_entry(manifest, plat, manifest_url())

    blob = _http_get(entry["url"], binary=True)

    sha = entry.get("sha256")
    if sha:
        _verify_sha256(blob, sha)
    else:
        _warn(quiet, "warning: manifest provided no sha256 — skipping integrity check.")

    # Never cache/exec a macOS binary this CPU cannot run — fail clearly instead
    # of leaving a wrong-arch binary that errors with "Bad CPU type" on every run.
    _verify_runnable_arch(blob, quiet)

    os.makedirs(cache_dir(), exist_ok=True)
    tmp = path + ".part"
    with open(tmp, "wb") as fh:
        fh.write(blob)
    if plat != "windows":
        mode = os.stat(tmp).st_mode
        os.chmod(tmp, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    os.replace(tmp, path)

    identity = entry.get("identity") or ""
    try:
        with open(_version_marker(), "w", encoding="utf-8") as fh:
            fh.write(identity)
    except OSError:
        pass
    _mark_checked()

    _warn(quiet, f"sast: installed engine {identity or '(unversioned)'} -> {path}")
    return path


def _warn(quiet: bool, msg: str) -> None:
    if not quiet:
        print(msg, file=sys.stderr)
