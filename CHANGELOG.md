# Changelog — `sast` launcher

`pip install sast` / `npm i -g @insom/insom` install a small launcher that
fetches the OS-matched Insomnia SAST engine from insom.ai on first run
(checksum-verified, cached, auto-updating). This file tracks the launcher;
engine capabilities are noted where they change what you get.

## 1.7.0 — 2026-10-10
- **Engine refreshed to the v3.4.9 build** (`2026.10.10-d64ba9e`). No launcher
  changes are required to get it — the launcher is version-independent and
  auto-updates the cached engine from the insom.ai manifest — this bump simply
  advertises the new engine and its benchmark. Run `sast self-update` to pull it
  immediately.
- **Engine capabilities (what you get):** scanner module count 1443 → **1472**
  (+16 modern attack classes: PortSwigger Top-10 2024–2025 DAST — parser
  differentials, ORM leak, HTTP/2 Rapid Reset precondition, SSRF→cloud-metadata,
  postMessage/service-worker/CSP-gadget/error-SSTI; OWASP API Top-10 — OpenAPI
  security lint, business-flow abuse, SSE/gRPC-web discovery; the 2025 MCP CVE
  cluster; and a CI/CD + AI/ML SAST rule pack). Current SAST benchmark ≈ 98.8%
  coverage / 96.7% recall with a 0.0% false-positive gate on the reference suite.

## 1.6.5 — 2026-06-11
- **Intel macOS, the real fix.** The launcher now resolves the Intel build from
  the `macos-x64` manifest key (where CI actually publishes it) instead of the
  stale legacy `macos` key, so Intel Macs get the genuine x86_64 engine. Apple
  Silicon resolves `macos-arm64` first, then `macos-x64` (Rosetta). Combined with
  the v1.6.4 Mach-O arch check, an Intel Mac can no longer end up with an arm64
  binary.

## 1.6.4 — 2026-06-11
- **Intel macOS fix.** The launcher now verifies the downloaded engine's CPU
  architecture (Mach-O) before caching or running it. An arm64 binary cannot run
  on an Intel Mac, and exec'ing it gave a cryptic `OSError: [Errno 86] Bad CPU
  type in executable`; you now get a clear, actionable message instead, and a
  binary the host can't run is never cached. (The underlying cause — the
  `macos-x64` download serving an arm64 build — is fixed on the build/CI side so
  Intel Macs get a real x86_64 engine again.)

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
