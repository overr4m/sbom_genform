"""Smoke tests — import and basic unit checks (no external tools required)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from sbom_pipeline import cli
from sbom_pipeline import __version__
from sbom_pipeline.config import PipelineConfig
from sbom_pipeline.dedup import dedup_sbom
from sbom_pipeline.exporter import Exporter
from sbom_pipeline.sign import sign_sbom, verify_sbom
from sbom_pipeline.vuln_merger import VulnFinding, merge_vulns_into_sbom


_MINIMAL_SBOM: dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"type": "library", "name": "requests", "version": "2.31.0",
         "purl": "pkg:pypi/requests@2.31.0", "bom-ref": "r1"},
        {"type": "library", "name": "requests", "version": "2.31.0",
         "purl": "pkg:pypi/requests@2.31.0", "bom-ref": "r2"},
        {"type": "library", "name": "flask", "version": "3.0.0",
         "purl": "pkg:pypi/flask@3.0.0", "bom-ref": "f1"},
    ],
}

_CLI_RUNNER = CliRunner()


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

def test_version_is_semver():
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def test_cli_no_bdu_overrides_bdu_env(monkeypatch):
    captured: dict[str, bool] = {}

    def fake_pipeline_run(cfg: PipelineConfig) -> None:
        captured["use_bdu"] = cfg.use_bdu

    monkeypatch.setenv("BDU", "true")
    monkeypatch.setattr(cli, "pipeline_run", fake_pipeline_run)
    monkeypatch.setattr(cli, "_print_banner", lambda: None)
    monkeypatch.setattr(cli, "_print_footer", lambda: None)
    monkeypatch.setattr(cli, "setup_logging", lambda verbose: None)

    result = _CLI_RUNNER.invoke(cli.app, ["run", "--no-bdu"])

    assert result.exit_code == 0
    assert captured["use_bdu"] is False


def test_cli_bdu_enables_use_bdu(monkeypatch):
    captured: dict[str, bool] = {}

    def fake_pipeline_run(cfg: PipelineConfig) -> None:
        captured["use_bdu"] = cfg.use_bdu

    monkeypatch.delenv("BDU", raising=False)
    monkeypatch.setattr(cli, "pipeline_run", fake_pipeline_run)
    monkeypatch.setattr(cli, "_print_banner", lambda: None)
    monkeypatch.setattr(cli, "_print_footer", lambda: None)
    monkeypatch.setattr(cli, "setup_logging", lambda verbose: None)

    result = _CLI_RUNNER.invoke(cli.app, ["run", "--bdu"])

    assert result.exit_code == 0
    assert captured["use_bdu"] is True


def test_config_defaults():
    cfg = PipelineConfig()
    assert cfg.source == "local"
    assert cfg.skip_clair is True
    assert cfg.use_bdu is False
    assert cfg.project_dir == Path("examples/project_inject")


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("SOURCE", "github")
    monkeypatch.setenv("GIT_URL", "https://github.com/org/repo")
    monkeypatch.setenv("SKIP_CLAIR", "false")
    monkeypatch.setenv("BDU", "true")
    cfg = PipelineConfig.from_env()
    assert cfg.source == "github"
    assert cfg.git_url == "https://github.com/org/repo"
    assert cfg.skip_clair is False
    assert cfg.use_bdu is True


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------

def test_dedup_removes_duplicates():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        inp = p / "bom.json"
        out = p / "bom-dedup.json"
        inp.write_text(json.dumps(_MINIMAL_SBOM))

        dedup_sbom(inp, out)

        result = json.loads(out.read_text())
        assert len(result["components"]) == 2


# ---------------------------------------------------------------------------
# Sign & Verify
# ---------------------------------------------------------------------------

def test_sign_and_verify():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        inp = p / "bom.json"
        out = p / "bom-signed.json"
        inp.write_text(json.dumps(_MINIMAL_SBOM))

        sign_sbom(inp, out)
        assert out.exists()

        ok = verify_sbom(out)
        assert ok is True


def test_verify_fails_on_tampered_sbom():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        inp = p / "bom.json"
        out = p / "bom-signed.json"
        inp.write_text(json.dumps(_MINIMAL_SBOM))

        sign_sbom(inp, out)

        data = json.loads(out.read_text())
        data["components"].append({"name": "evil", "version": "0.0.1"})
        out.write_text(json.dumps(data))

        ok = verify_sbom(out)
        assert ok is False


# ---------------------------------------------------------------------------
# VulnMerger
# ---------------------------------------------------------------------------

def test_merge_vulns_into_sbom():
    sbom = json.loads(json.dumps(_MINIMAL_SBOM))
    findings = [
        VulnFinding(
            cve_id="CVE-2023-1234",
            scanner="trivy",
            component_name="requests",
            component_version="2.31.0",
            component_purl="pkg:pypi/requests@2.31.0",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vuln",
            fixed_version="2.32.0",
        )
    ]
    result = merge_vulns_into_sbom(sbom, findings)
    vulnerability = result["vulnerabilities"][0]

    assert "vulnerabilities" in result
    assert vulnerability["id"] == "CVE-2023-1234"
    assert "properties" not in vulnerability



def test_merge_vulns_with_bdu_into_sbom():
    sbom = json.loads(json.dumps(_MINIMAL_SBOM))
    findings = [
        VulnFinding(
            cve_id="CVE-2023-1234",
            bdu_id="BDU:2023-01813",
            scanner="trivy",
            component_name="requests",
            component_version="2.31.0",
            component_purl="pkg:pypi/requests@2.31.0",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vuln",
            fixed_version="2.32.0",
        )
    ]
    result = merge_vulns_into_sbom(sbom, findings)
    vulnerability = result["vulnerabilities"][0]

    assert "vulnerabilities" in result
    assert vulnerability["id"] == "CVE-2023-1234"
    assert vulnerability["properties"] == [
        {"name": "ru.fstec.bdu:id", "value": "BDU:2023-01813"}
    ]


def test_exporter_hides_bdu_column_when_disabled():
    findings = [
        VulnFinding(
            cve_id="CVE-2023-1234",
            bdu_id="BDU:2023-01813",
            scanner="trivy",
            component_name="requests",
            component_version="2.31.0",
            component_purl="pkg:pypi/requests@2.31.0",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vuln",
            fixed_version="2.32.0",
        )
    ]

    exporter = Exporter([], vulns=findings)
    vuln_rows = exporter._vuln_rows()

    assert exporter._vuln_columns() == [
        "Компонент",
        "Версия",
        "CVE / ID",
        "CVSS",
        "Критичность",
        "Описание",
        "Сканер",
        "Исправлено в версии",
    ]
    assert "BDU / ID" not in vuln_rows[0]


def test_exporter_shows_bdu_column_when_enabled():
    findings = [
        VulnFinding(
            cve_id="CVE-2023-1234",
            bdu_id="BDU:2023-01813",
            scanner="trivy",
            component_name="requests",
            component_version="2.31.0",
            component_purl="pkg:pypi/requests@2.31.0",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vuln",
            fixed_version="2.32.0",
        )
    ]

    exporter = Exporter([], vulns=findings, include_bdu=True)
    vuln_rows = exporter._vuln_rows()

    assert exporter._vuln_columns() == [
        "Компонент",
        "Версия",
        "CVE / ID",
        "BDU / ID",
        "CVSS",
        "Критичность",
        "Описание",
        "Сканер",
        "Исправлено в версии",
    ]
    assert vuln_rows[0]["BDU / ID"] == "BDU:2023-01813"
