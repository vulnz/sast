# sast

**Free, fast static application security testing for CI/CD.**

`sast` is a tiny launcher. Installing it is instant; the first time you run it,
it downloads a self-contained SAST engine binary that matches your operating
system, verifies its checksum, and caches it. Every run after that is native
speed with no Python dependencies.

```bash
pip install sast
sast .                       # scan the current directory
sast ./src -f sarif -o out   # write a SARIF report into ./out
sast . --fail-on high        # exit non-zero on high+ findings (CI gating)
sast --help                  # full engine options
```

**Coverage at a glance:** 1,750+ FP-validated rules · native AST + cross-file
taint on **16 languages** (regex for 40+) · 230+ secret rule packs with **live
key validation** · SCA across 8+ ecosystems + container/OS packages · ~24,000
CMS advisories · web-shell & malware signatures · IaC (Terraform/K8s/Docker/
CloudFormation) · **SARIF / JSON / HTML**.

> Supports Linux, macOS and Windows (x86-64). On Apple Silicon the macOS
> binary runs under Rosetta.

## Installing

`pip install sast` creates a `sast` command (Linux/macOS: `<prefix>/bin/sast`,
Windows: `<prefix>\Scripts\sast.exe`). For the command to be found, that
directory must be on your `PATH`. The most reliable options:

```bash
pipx install sast      # recommended — isolated, always on PATH (all OSes)
```

or inside a virtual environment:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate
pip install sast
```

**If `sast` is "not recognized" / "command not found"** after a
`pip install --user`, the per-user scripts dir isn't on your `PATH`. Either
add it, or just run it as a module — this always works regardless of `PATH`:

```bash
python -m sast .
```

- **Windows** per-user scripts dir: `%APPDATA%\Python\Python3XX\Scripts`
- **Linux/macOS** per-user scripts dir: `~/.local/bin`

## What it scans

A single self-contained binary — **no Python dependencies and no external
tools shelled out** (no semgrep / trivy / bandit; everything runs in-engine):

- **Code vulnerabilities** — a native tree-sitter **AST + taint engine** across
  **16 languages** (Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C,
  C++, C#, Rust, Kotlin, Scala, Swift, Lua, Shell) plus regex coverage for
  40+, with **intra- *and* cross-file taint** that follows `include` / `require`
  / `import` relationships (source in one file → sink in another).
- **Secrets & API keys** — entropy + 230+ vendor rule packs, with optional
  **live validation** that labels each secret *validated* / *invalid* / *not
  validated* against its provider.
- **Vulnerable dependencies (SCA)** — OSV / advisory matching across npm, pip,
  Maven, Go, Composer, Cargo and more (covers `npm audit`-style checks).
- **Vulnerable JS libraries** — RetireJS-style detection of bundled jQuery,
  AngularJS, lodash, Bootstrap, Handlebars, … versions with known CVEs.
- **CMS vulnerable components** — WordPress / Joomla / Drupal / Magento
  plugins, themes and core matched against **~24,000 advisories**.
- **Web shells & malware** — PHP / ASP(X) / JSP / shellcode signatures
  (c99, r57, WSO, China Chopper, …), obfuscated payloads, reverse shells, and
  suspicious **double-extension uploads** (`shell.php.jpg`).
- **IaC / cloud misconfiguration** — Terraform, Kubernetes, Docker, CloudFormation, …
- Output as **HTML**, **TXT**, **JSON** or **SARIF 2.1.0** (drops straight into
  GitHub code scanning), with CI exit-code gating via `--fail-on`.

## How it compares

Most **free** scanners do exactly one thing — Bandit is Python-only SAST,
Checkov is IaC-only, Gitleaks is secrets-only, Trivy is SCA/containers. The
all-in-one platforms (Semgrep, Snyk) put taint analysis, secrets and SCA behind
a **paid** tier. `sast` does the whole lot in a single **free** binary — no
external tools shelled out, runs **offline**.

| Capability | **sast** (Insomnia) | Semgrep | Snyk | Bandit | Checkov | Trivy | Gitleaks |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Multi-language SAST + taint | ✅ 16 langs | ◑ taint = paid | ✅ | ◑ Python | ✗ | ✗ | ✗ |
| Cross-file taint (include/import) | ✅ | ◑ | ◑ | ✗ | ✗ | ✗ | ✗ |
| Secrets + **live key validation** | ✅ | ◑ paid | ◑ | ✗ | ✗ | ◑ | ◑ no val. |
| Dependencies / SCA (CVEs) | ✅ | ◑ paid | ✅ | ✗ | ◑ | ✅ | ✗ |
| Vulnerable JS libs (RetireJS) | ✅ | ✗ | ◑ | ✗ | ✗ | ✗ | ✗ |
| CMS CVEs (WordPress/Joomla/…) | ✅ ~24k | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Web-shell & malware detection | ✅ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| IaC / cloud misconfig | ✅ | ✅ | ✅ | ✗ | ✅ | ✅ | ✗ |
| Container / OS-package CVEs | ✅ | ✗ | ✅ | ✗ | ✗ | ✅ | ✗ |
| SARIF output | ✅ | ✅ | ✅ | ◑ | ✅ | ✅ | ✅ |
| Editor plugins (VS Code/JetBrains) | ✅ | ✅ | ✅ | ✗ | ✗ | ✗ | ✗ |
| Git pre-push gate | ✅ | ◑ | ◑ | ✗ | ✗ | ✗ | ◑ |
| Single offline binary, no extra tools | ✅ | ✗ | ✗ | ✗ | ✗ | ✅ | ✅ |
| **Free** (no paywalled core) | ✅ | ◑ | ✗ | ✅ | ✅ | ✅ | ✅ |

✅ built-in · ◑ partial / paid tier · ✗ not offered

> Reflects each tool's free/open-source offering as of mid-2026; paid platform
> tiers may add capabilities. In short: instead of stitching together
> Bandit + Gitleaks + Trivy + Checkov (and paying Semgrep/Snyk for taint + SCA),
> you get one free engine that covers all of it.

## Editor & CI integrations

Same engine, everywhere:

- **VS Code** — the *Insomnia SAST* extension: inline hints as you type, a
  **Vulnerabilities** panel, an **All Issues** dashboard, mark-as-false-positive,
  and a git **pre-push gate**. Install from the VS Code Marketplace or
  <https://insom.ai/plugin>.
- **JetBrains** (PyCharm / PhpStorm / WebStorm / GoLand / IntelliJ) and
  **Visual Studio 2022** — in beta.
- **CI** — `pip install sast && sast . -f sarif -o out --fail-on high`, then
  upload `out/*.sarif` to GitHub code scanning.

## How it works

`pip install sast` lays down only a few KB of pure-Python launcher — **no
download happens at install time** (that keeps offline/CI installs reliable).
On first invocation the launcher:

1. Detects your OS → `linux` / `macos` / `windows`.
2. Fetches `https://insom.ai/static/downloads/plugin_manifest.json` and reads
   its `sast.<os>` entry (filename + sha256 + version).
3. Downloads the matching binary and verifies its `sha256`.
4. Caches it under your per-user cache directory and `exec`s it.

Because the engine lives on the server, new engine releases reach users
without republishing the pip package.

### Staying on the latest engine

After the first download the cached binary is reused for speed. At most once
per day (`SAST_UPDATE_INTERVAL`, default `86400` seconds) `sast` also asks
insom.ai whether a newer engine is published and, if so, upgrades itself
automatically. Update checks **fail open** — if you're offline or the server
is unreachable, the cached binary keeps working. Set `SAST_UPDATE_INTERVAL=0`
to pin the cached version, or run `sast self-update` to force the latest at
any time.

## Launcher commands

| Command             | What it does                                  |
|---------------------|-----------------------------------------------|
| `sast …`            | Forward all args to the SAST engine           |
| `sast self-update`  | Re-download the latest engine binary          |
| `sast self-version` | Show launcher + cached-engine versions        |
| `sast self-where`   | Print the cached binary path                  |

## Environment variables

| Variable                | Purpose                                                    |
|-------------------------|------------------------------------------------------------|
| `SAST_MANIFEST_URL`     | Override the manifest URL (staging / self-hosting)         |
| `SAST_CACHE_DIR`        | Override where the binary is cached                        |
| `SAST_UPDATE_INTERVAL`  | Seconds between auto-update checks (default `86400`; `0` disables) |

Default cache locations:

- **Linux:** `~/.cache/sast/bin`
- **macOS:** `~/Library/Application Support/sast/bin`
- **Windows:** `%LOCALAPPDATA%\sast\bin`

## Use in CI (GitHub Actions)

```yaml
- run: pip install sast
- run: sast . -f sarif -o sarif-out --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sarif-out      # the action accepts a directory of .sarif files
```

`sast` exits non-zero when findings meet your `--fail-on` threshold, failing
the build.

## Server-side manifest format

By default the launcher reads insom.ai's `plugin_manifest.json`, whose `sast`
section lists the latest per-OS build:

```json
{
  "sast": {
    "windows": { "filename": "insomnia-sast-windows-x64.exe", "sha256": "<hex>", "version": "1.0.0", "uploaded": "<iso8601>" },
    "linux":   { "filename": "insomnia-sast-linux-x64",       "sha256": "<hex>", "version": "1.0.0", "uploaded": "<iso8601>" },
    "macos":   null
  }
}
```

`filename` is resolved relative to the manifest URL. The launcher also accepts
a simpler `{ "version", "platforms": { "<os>": { "url", "sha256" } } }` shape if
you self-host via `SAST_MANIFEST_URL`. `sha256` is enforced when present; a
`null` OS entry means that build isn't published yet.

---

© CQR Cybersecurity LLC. The `sast` launcher is open source; the SAST engine
binary it downloads is proprietary. See <https://insom.ai>.
