# Changelog — `sast` launcher

`pip install sast` / `npm i -g @insom/insom` install a small launcher that
fetches the OS-matched Insomnia SAST engine from insom.ai on first run
(checksum-verified, cached, auto-updating). This file tracks the launcher;
engine capabilities are noted where they change what you get.

## 1.6.2 — 2026-06-11
- Engine updated to **v1.8.1**: inter-procedural taint across files, gap-fill
  rule packs (SQLi / SSRF / stored-XSS / IaC), Trivy-style container CVE matching
  in SCA, an offline OSV mirror for air-gapped scans, and live secret validation
  on by default.
- Synced the launcher's internal `__version__` to the published package version
  (was drifting at 1.5.0).

## 1.6.1 — TLS fix
- Use the `certifi` CA bundle so the first-run engine fetch works on macOS
  python.org builds.

## 1.6.0 — native linux-arm64
- Native linux-arm64 engine support.

## 1.5.x
- Docs: coverage stats and tool comparison; SARIF CLI examples; refreshed PyPI
  long description.

## 0.1.x / first releases
- Read insom.ai `plugin_manifest.json` directly so engine downloads resolve.
- Daily auto-update with fail-open behaviour (`SAST_UPDATE_INTERVAL`).
- Renamed launcher `ins` → `sast` (`pip install sast`).
