"""Smoke tests — import and basic unit checks (no external tools required)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from sbom_pipeline import __version__
from sbom_pipeline.config import PipelineConfig
from sbom_pipeline.dedup import dedup_sbom
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

def test_config_defaults():
    cfg = PipelineConfig()
    assert cfg.source == "local"
    assert cfg.skip_clair is True
    assert cfg.project_dir == Path("examples/project_inject")


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("SOURCE", "github")
    monkeypatch.setenv("GIT_URL", "https://github.com/org/repo")
    monkeypatch.setenv("SKIP_CLAIR", "false")
    cfg = PipelineConfig.from_env()
    assert cfg.source == "github"
    assert cfg.git_url == "https://github.com/org/repo"
    assert cfg.skip_clair is False


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
    assert "vulnerabilities" in result
    assert result["vulnerabilities"][0]["id"] == "CVE-2023-1234"
