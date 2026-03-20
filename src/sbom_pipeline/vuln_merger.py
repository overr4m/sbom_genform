"""Модель данных уязвимостей и встраивание в CycloneDX SBOM."""

from __future__ import annotations

import copy
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class VulnFinding:
    """Нормализованная уязвимость из любого сканера."""

    cve_id: str
    component_name: str
    component_version: str
    component_purl: str
    cvss_score: float
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    description: str
    scanner: str           # trivy | clair | dependency-check
    fixed_version: str = ""

    @property
    def severity_upper(self) -> str:
        return self.severity.upper()


def merge_vulns_into_sbom(
    sbom: Dict[str, Any],
    findings: List[VulnFinding],
) -> Dict[str, Any]:
    """
    Встроить список VulnFinding в SBOM как массив «vulnerabilities»
    (стандарт CycloneDX 1.4+).
    """
    if not findings:
        return sbom

    sbom = copy.deepcopy(sbom)

    # Индекс компонентов: purl → bom-ref  /  name@version → bom-ref
    comp_index: Dict[str, str] = {}
    for comp in sbom.get("components", []):
        purl = comp.get("purl", "")
        name = comp.get("name", "")
        version = comp.get("version", "")
        bom_ref = comp.get("bom-ref") or f"{name}@{version}"
        if purl:
            comp_index[purl] = bom_ref
        comp_index[f"{name}@{version}"] = bom_ref

    vulns: list[Dict[str, Any]] = []
    for f in findings:
        ref = (
            comp_index.get(f.component_purl)
            or comp_index.get(f"{f.component_name}@{f.component_version}")
            or f"{f.component_name}@{f.component_version}"
        )

        entry: Dict[str, Any] = {
            "id": f.cve_id,
            "source": {"name": f.scanner.upper()},
            "ratings": [
                {
                    "score": f.cvss_score,
                    "severity": f.severity.lower(),
                    "method": "CVSSv3",
                }
            ],
            "description": f.description,
            "affects": [{"ref": ref}],
        }
        if f.fixed_version:
            entry["recommendation"] = f"Обновить до версии {f.fixed_version}"

        vulns.append(entry)

    sbom["vulnerabilities"] = vulns
    logging.info(f"[vuln_merger] Добавлено {len(vulns)} уязвимостей в SBOM")
    return sbom


def save_vuln_report(findings: List[VulnFinding], path: Path) -> None:
    """Сохранить нормализованные уязвимости как JSON (для отладки / аудита)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [
        {
            "cve_id": f.cve_id,
            "component": f.component_name,
            "version": f.component_version,
            "purl": f.component_purl,
            "cvss": f.cvss_score,
            "severity": f.severity_upper,
            "description": f.description,
            "scanner": f.scanner,
            "fixed_version": f.fixed_version,
        }
        for f in findings
    ]
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)
    logging.info(f"[vuln_merger] Нормализованные уязвимости → {path}")
