# sast

**Free, fast static application security testing for CI/CD.**

`sast` is a tiny launcher. Installing it is instant; the first time you run it,
it downloads a self-contained SAST engine binary that matches your operating
system, verifies its checksum, and caches it. Every run after that is native
speed with no Python dependencies.

```bash
pip install sast
sast .                 # scan the current directory
sast ./src --sarif report.sarif
sast --help            # full engine options
```

> Supports Linux, macOS and Windows (x86-64). On Apple Silicon the macOS
> binary runs under Rosetta.

## What it scans

- **SAST** across 17+ languages with taint tracking
- **Secrets** detection (entropy + vendor rule packs)
- **IaC / cloud misconfiguration** (Terraform, K8s, Docker, …)
- **SCA** — known-vulnerable dependencies
- Output as **HTML**, **JSON**, or **SARIF** (drops straight into GitHub code scanning)

## How it works

`pip install sast` lays down only a few KB of pure-Python launcher — **no
download happens at install time** (that keeps offline/CI installs reliable).
On first invocation the launcher:

1. Detects your OS → `linux` / `macos` / `windows`.
2. Fetches the manifest from `https://insom.ai/static/downloads/sast/manifest.json`.
3. Downloads the matching binary and verifies its `sha256`.
4. Caches it under your per-user cache directory and `exec`s it.

Because the engine lives on the server, new engine releases reach users
without republishing the pip package.

## Launcher commands

| Command             | What it does                                  |
|---------------------|-----------------------------------------------|
| `sast …`            | Forward all args to the SAST engine           |
| `sast self-update`  | Re-download the latest engine binary          |
| `sast self-version` | Show launcher + cached-engine versions        |
| `sast self-where`   | Print the cached binary path                  |

## Environment variables

| Variable             | Purpose                                                       |
|----------------------|---------------------------------------------------------------|
| `SAST_MANIFEST_URL`  | Override the manifest URL (staging / self-hosting)            |
| `SAST_CACHE_DIR`     | Override where the binary is cached                           |

Default cache locations:

- **Linux:** `~/.cache/sast/bin`
- **macOS:** `~/Library/Application Support/sast/bin`
- **Windows:** `%LOCALAPPDATA%\sast\bin`

## Use in CI (GitHub Actions)

```yaml
- run: pip install sast
- run: sast . --sarif results.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`sast` exits non-zero when findings meet your `--fail-on` threshold, failing
the build.

## Server-side manifest format

The launcher expects this JSON at `SAST_MANIFEST_URL`:

```json
{
  "version": "2026.06.04-abc1234",
  "platforms": {
    "linux":   { "url": "sast-linux-x64",       "sha256": "<hex>" },
    "macos":   { "url": "sast-macos-x64",        "sha256": "<hex>" },
    "windows": { "url": "sast-windows-x64.exe",  "sha256": "<hex>" }
  }
}
```

`url` may be relative to the manifest URL or absolute. `sha256` is optional but
enforced when present.

---

© CQR Cybersecurity LLC. The `sast` launcher is open source; the SAST engine
binary it downloads is proprietary. See <https://insom.ai>.
