---
name: sca
description: Run Software Composition Analysis (SCA), OSV dependency CVE lookup, dependency-confusion detection, vulnerable JS library detection, CMS plugin/theme CVE matching, and dependency license auditing using our `sast` library. Use when auditing third-party packages, lockfiles, containers, or open-source licenses.
argument-hint: "[path] [--licenses] [--osv-mode both|offline|api]"
---

# SAST Dependency CVE & License Audit (`/sast:sca`)

Audit project dependencies, lockfiles, container manifests, bundled JS libraries, CMS components, and open-source licenses using our `sast` library's built-in SCA engine.

## What Is Checked
- **Package Ecosystems**: npm (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`), PyPI (`requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`), Go (`go.mod`, `go.sum`), Maven/Gradle (`pom.xml`, `build.gradle`), Cargo (`Cargo.toml`, `Cargo.lock`), Composer (`composer.json`, `composer.lock`), NuGet, and RubyGems.
- **Dependency Confusion**: Detects internal/unclaimed package names exposed to public registry substitution.
- **Bundled Frontend JS Libraries**: RetireJS-style fingerprinting of jQuery, AngularJS, lodash, Bootstrap, Handlebars, etc.
- **CMS Advisories**: WordPress, Joomla, Drupal, and Magento plugin/theme/core matching against ~24,000 CVEs.
- **License Risk Audit (`--licenses`)**: Flags copyleft (`GPL`, `AGPL`) and proprietary/restrictive licenses across manifests and installed packages.

## Commands

```bash
# Run SAST + SCA + License risk audit
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" ${ARGUMENTS:-.} --licenses --claude-summary

# Offline SCA using local OSV mirror only (air-gapped mode)
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" . --osv-mode offline --licenses --claude-summary

# Refresh or build the local OSV vulnerability mirror database
python "${CLAUDE_PLUGIN_ROOT}/scripts/sast_runner.py" --update-osv-db COMMON
```

## Reporting Instructions
1. Group vulnerable packages by manifest file and severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
2. List the affected package name, installed version, CVE/GHSA advisory ID, and fixed version.
3. Provide the exact upgrade command (`npm install pkg@version`, `pip install 'pkg>=version'`, etc.) and flag any potential semver breaking changes.
4. Summarize any risky or incompatible licenses identified by `--licenses`.
