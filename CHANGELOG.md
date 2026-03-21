# Changelog

All notable changes to **sbom-pipeline** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [2.0.0] — 2026-03-21

### Added
- Pure Python pipeline — no shell scripts anywhere
- `sbom-pipeline run` / `sbom` CLI (typer + rich) with subcommands `run`, `format`, `verify`
- `--version` / `-V` flag on the root command
- Short entry-point alias `sbom` alongside `sbom-pipeline`
- SBOM generation from local directory, GitHub, or GitLab via GitPython
- Auto-detection of project type (Python → cyclonedx-py, others → cdxgen fallback)
- Pure-Python deduplication by PURL key (`dedup.py`)
- SHA-256 signing embedded in `metadata.signature` + `.sig` sidecar file (`sign.py`)
- Vulnerability scanning: Trivy (fs + sbom), OWASP Dependency-Check, Clair (optional)
- `VulnFinding` dataclass — normalised vulnerability model across all scanners
- Vulnerability injection into CycloneDX `vulnerabilities[]` array (`vuln_merger.py`)
- Human-readable reports: Excel (.xlsx, 2 sheets), Word (.docx), ODT (.odt)
- Component-to-vulnerability mapping in all report formats
- `pyproject.toml` single-file packaging with `hatchling`
- GitHub Actions CI workflow (lint + test matrix 3.11–3.13)
- GitHub Actions publish workflow with PyPI Trusted Publishing (OIDC)
- GitLab CI include template (`secgensbom/secgensbom.yml`)
- Docker images: `docker/Dockerfile.secgensbom`, `docker/Dockerfile.formatter`
- Vulnerable PHP demo project moved to `examples/project_inject/`

### Removed
- All shell scripts (`pipeline.sh`, `scan_trivy.sh`, `scan_clair.sh`, etc.)
- Legacy `script/` Python package
- Submodule references (`.gitmodules`)

### Changed
- Default `project_dir` changed from `project_inject/` to `examples/project_inject/`
- Docker entrypoints now call `sbom-pipeline` CLI directly

---

## [1.x] — legacy

Shell-script-based pipeline. See git history for details.

[Unreleased]: https://github.com/geminishkv/sbom_genformatter/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/geminishkv/sbom_genformatter/releases/tag/v2.0.0
