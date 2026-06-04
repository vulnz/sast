# ins

**Free, fast static application security testing for CI/CD.**

`ins` is a tiny launcher. Installing it is instant; the first time you run it,
it downloads a self-contained SAST engine binary that matches your operating
system, verifies its checksum, and caches it. Every run after that is native
speed with no Python dependencies.

```bash
pip install ins
ins .                 # scan the current directory
ins ./src --sarif report.sarif
ins --help            # full engine options
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

`pip install ins` lays down only a few KB of pure-Python launcher — **no
download happens at install time** (that keeps offline/CI installs reliable).
On first invocation the launcher:

1. Detects your OS → `linux` / `macos` / `windows`.
2. Fetches the manifest from `https://insom.ai/static/downloads/ins/manifest.json`.
3. Downloads the matching binary and verifies its `sha256`.
4. Caches it under your per-user cache directory and `exec`s it.

Because the engine lives on the server, new engine releases reach users
without republishing the pip package.

## Launcher commands

| Command            | What it does                                  |
|--------------------|-----------------------------------------------|
| `ins …`            | Forward all args to the SAST engine           |
| `ins self-update`  | Re-download the latest engine binary          |
| `ins self-version` | Show launcher + cached-engine versions        |
| `ins self-where`   | Print the cached binary path                  |

## Environment variables

| Variable            | Purpose                                                        |
|---------------------|----------------------------------------------------------------|
| `INS_MANIFEST_URL`  | Override the manifest URL (staging / self-hosting)             |
| `INS_CACHE_DIR`     | Override where the binary is cached                            |

Default cache locations:

- **Linux:** `~/.cache/ins/bin`
- **macOS:** `~/Library/Application Support/ins/bin`
- **Windows:** `%LOCALAPPDATA%\ins\bin`

## Use in CI (GitHub Actions)

```yaml
- run: pip install ins
- run: ins . --sarif results.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`ins` exits non-zero when findings meet your `--fail-on` threshold, failing
the build.

## Server-side manifest format

The launcher expects this JSON at `INS_MANIFEST_URL`:

```json
{
  "version": "2026.06.04-abc1234",
  "platforms": {
    "linux":   { "url": "ins-linux-x64",       "sha256": "<hex>" },
    "macos":   { "url": "ins-macos-x64",        "sha256": "<hex>" },
    "windows": { "url": "ins-windows-x64.exe",  "sha256": "<hex>" }
  }
}
```

`url` may be relative to the manifest URL or absolute. `sha256` is optional but
enforced when present.

---

© CQR Cybersecurity LLC. The `ins` launcher is open source; the SAST engine
binary it downloads is proprietary. See <https://insom.ai>.
