<p align="center">
  <a href="https://insom.ai/en/plugin">
    <img src="https://insom.ai/static/img/logo.png" width="96" alt="Insomnia">
  </a>
</p>

<h1 align="center">sast — by Insomnia</h1>

<p align="center">
  <b>Free, fast static application security testing for your terminal &amp; CI/CD.</b><br>
  SAST + taint · secrets with live key validation · SCA/CVEs · IaC · CMS &amp; web-shell/malware —
  <i>one self-contained binary</i>, the same engine in your IDE and your build.
</p>

<p align="center">
  <a href="https://pypi.org/project/sast/"><img src="https://img.shields.io/pypi/v/sast?color=7c3aed&label=pip%20install%20sast&logo=python&logoColor=white" alt="PyPI"></a>
  <a href="https://github.com/vulnz/homebrew-sast"><img src="https://img.shields.io/badge/brew-vulnz%2Fsast-2563eb?logo=homebrew&logoColor=white" alt="Homebrew"></a>
  <a href="https://www.npmjs.com/package/sastai"><img src="https://img.shields.io/npm/v/sastai?color=cb3837&label=npm%20i%20-g%20sastai&logo=npm&logoColor=white" alt="npm"></a>
  <a href="https://github.com/vulnz/sast/pkgs/container/sast"><img src="https://img.shields.io/badge/ghcr.io-vulnz%2Fsast-2496ED?logo=docker&logoColor=white" alt="Docker image"></a>
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-16a34a" alt="Platforms">
  <img src="https://img.shields.io/badge/rules-1%2C750%2B-b45309" alt="Rules">
  <img src="https://img.shields.io/badge/price-free-16a34a" alt="Free">
</p>

<h3 align="center">Get the editor plugins — same engine, same results</h3>

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=InsomniaSAST.insomnia">
    <img src="https://img.shields.io/badge/VS%20Code-Install-007ACC?style=for-the-badge&logo=visualstudiocode&logoColor=white" alt="VS Code Marketplace">
  </a>
  &nbsp;
  <a href="https://open-vsx.org/extension/InsomniaSAST/insomnia">
    <img src="https://img.shields.io/badge/Open%20VSX-Install-A60EE5?style=for-the-badge&logo=eclipseide&logoColor=white" alt="Open VSX (VSCodium / Cursor / Windsurf / Gitpod)">
  </a>
  &nbsp;
  <a href="https://plugins.jetbrains.com/plugin/32214-insomnia-sast">
    <img src="https://img.shields.io/badge/JetBrains-Install-000000?style=for-the-badge&logo=jetbrains&logoColor=white" alt="JetBrains Marketplace">
  </a>
  &nbsp;
  <a href="https://github.com/marketplace/actions/sast-by-insomnia">
    <img src="https://img.shields.io/badge/GitHub%20Action-Use-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Marketplace Action">
  </a>
</p>

<p align="center">
  <a href="https://insom.ai/en/plugin"><b>Plugin home</b></a> ·
  <a href="https://insom.ai/en/sdlc"><b>CI/CD &amp; SDLC</b></a> ·
  <a href="https://insom.ai/en/downloads">Direct downloads</a> ·
  <a href="https://insom.ai/api/plugin/manifest">Manifest</a>
</p>

---

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

<p align="center">
  <a href="https://insom.ai/static/video/insomnia-sdlc-overview.mp4" title="Watch the Insomnia SAST overview">
    <img src="https://insom.ai/static/img/characters/02-insomnia-man-sitting-computer.png" width="62%" alt="Watch the Insomnia SAST overview video">
  </a>
  <br>
  <a href="https://insom.ai/static/video/insomnia-sdlc-overview.mp4"><b>▶ Watch the overview video</b></a>
  &nbsp;·&nbsp;
  <a href="https://insom.ai/en/sdlc">Read the SDLC walkthrough →</a>
</p>

**Coverage at a glance:** 1,750+ FP-validated rules · native AST + cross-file
taint on **16 languages** (regex for 40+) · 230+ secret rule packs with **live
key validation** · SCA across 8+ ecosystems + container/OS packages · ~24,000
CMS advisories · web-shell & malware signatures · IaC (Terraform/K8s/Docker/
CloudFormation) · **SARIF / JSON / HTML**.

> Supports Linux, macOS and Windows (x86-64). On Apple Silicon the macOS
> binary runs under Rosetta.

## Installing

Pick whichever fits your stack — every method lands the **same engine**.

| Method | Command |
|---|---|
| **pip / pipx** (any OS, Python 3.8+) | `pip install sast` &nbsp;·&nbsp; `pipx install sast` *(recommended — isolated, always on PATH)* |
| **Homebrew** (macOS / Linux) | `brew tap vulnz/sast && brew install sast` |
| **npm** (global launcher) | `sudo npm install -g sastai` |
| **Debian / Ubuntu** (signed apt repo) | see below — then `sudo apt-get install sast` |
| **Direct binary** (Fedora / Arch / Alpine / air-gapped) | `curl -sSL https://insom.ai/latest/sast/linux -o /usr/local/bin/sast` |

### Debian / Ubuntu — signed apt repo

```bash
curl -sSL https://insom.ai/apt/public-key.asc | sudo gpg --yes --dearmor \
  -o /usr/share/keyrings/insomnia-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/insomnia-archive-keyring.gpg] https://insom.ai/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/insomnia.list
sudo apt-get update && sudo apt-get install -y sast
```

### Direct download from insom.ai (no package manager)

A single self-contained binary — handy for air-gapped boxes and minimal CI images:

```bash
curl -sSL https://insom.ai/latest/sast/linux  -o /usr/local/bin/sast   # Linux x86-64
# curl -sSL https://insom.ai/latest/sast/macos -o /usr/local/bin/sast   # macOS
chmod +x /usr/local/bin/sast
sast --version
```

Windows: download `https://insom.ai/latest/sast/windows`, or grab any build from the
[**downloads page**](https://insom.ai/en/downloads). Files + SHA-256 are listed in the
[manifest](https://insom.ai/api/plugin/manifest).

### Notes on the pip install

`pip install sast` creates a `sast` command (Linux/macOS: `<prefix>/bin/sast`,
Windows: `<prefix>\Scripts\sast.exe`). For the command to be found, that
directory must be on your `PATH`. Inside a virtual environment:

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

## Run with Docker

A prebuilt, multi-arch (amd64 + arm64) image ships the engine baked in — nothing
to install, ideal for CI/CD. Available on both registries:

- **Docker Hub:** [`dominators/sast`](https://hub.docker.com/r/dominators/sast)
- **GHCR:** [`ghcr.io/vulnz/sast`](https://github.com/vulnz/sast/pkgs/container/sast)

```bash
docker pull dominators/sast:latest        # or: ghcr.io/vulnz/sast:latest
```

**Scan local source code** — mount your project at `/src`:

```bash
docker run --rm -v "$PWD:/src" dominators/sast:latest /src --fail-on high
```

```powershell
# Windows PowerShell
docker run --rm -v "${PWD}:/src" dominators/sast:latest /src --fail-on high
```

**Scan a remote repository** — pass a URL and the engine shallow-clones, scans,
and cleans up (no `git clone`, no volume mount needed):

```bash
docker run --rm dominators/sast:latest https://github.com/owner/repo --fail-on high
# private repo:
docker run --rm -e GITHUB_TOKEN=ghp_xxx dominators/sast:latest https://github.com/owner/private-repo
```

**Write reports** back to your working directory (SARIF for code scanning, HTML to read):

```bash
docker run --rm -v "$PWD:/src" dominators/sast:latest /src -f sarif,html -o /src/reports
```

In **GitHub Actions** the image works as a container step:

```yaml
- name: SAST
  run: docker run --rm -v "$PWD:/src" dominators/sast:latest /src -f sarif -o /src/out --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: out }
```

> Tip: pin a version (`ghcr.io/vulnz/sast:1.8.2`) for reproducible builds. The
> image runs as a non-root user and needs no API key, account, or telemetry.

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
  and a git **pre-push gate**.
  → [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=InsomniaSAST.insomnia)
  · [Open VSX](https://open-vsx.org/extension/InsomniaSAST/insomnia) (VSCodium / Cursor / Windsurf / Gitpod)
- **JetBrains** (PyCharm / PhpStorm / WebStorm / GoLand / IntelliJ IDEA / RubyMine /
  CLion / Rider / DataGrip) — one plugin for all of them.
  → [JetBrains Marketplace](https://plugins.jetbrains.com/plugin/32214-insomnia-sast)
- **Visual Studio 2022** and more entry points on the
  [plugin page](https://insom.ai/en/plugin).
- **GitHub Action** — drop SAST into any pipeline in one line, SARIF straight to the
  Security tab: [`SAST by Insomnia`](https://github.com/marketplace/actions/sast-by-insomnia).
- **CI (any)** — `pip install sast && sast . -f sarif -o out --fail-on high`, then
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
