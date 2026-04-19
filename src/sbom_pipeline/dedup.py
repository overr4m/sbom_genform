"""Дедупликация компонентов и уязвимостей SBOM — чистый Python."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from .vuln_merger import VulnFinding


def _merge_component(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    """
    Перенести все полезные данные из source в target (in-place).

    Применяется при дедупликации: если один компонент попал в SBOM
    из нескольких источников (cdxgen + Clair и т.п.), все полезные
    свойства объединяются в одну запись.
    """
    # --- properties (union by name; предпочитаем непустое значение) ---
    if source.get("properties"):
        target_props: List[Dict[str, str]] = target.setdefault("properties", [])
        by_name: Dict[str, Dict[str, str]] = {
            p.get("name", ""): p for p in target_props if isinstance(p, dict)
        }
        for prop in source["properties"]:
            if not isinstance(prop, dict):
                continue
            pname = prop.get("name", "")
            pval = prop.get("value", "")
            if pname not in by_name:
                target_props.append(prop)
                by_name[pname] = prop
            elif not by_name[pname].get("value") and pval:
                by_name[pname]["value"] = pval

    # --- скалярные поля (заполняем только если у target пусто) ---
    for field in ("cpe", "description", "purl", "version", "bom-ref"):
        if not target.get(field) and source.get(field):
            target[field] = source[field]

    # --- licenses (union by JSON-ключ) ---
    if source.get("licenses"):
        existing_lic: set = {
            json.dumps(lic, sort_keys=True)
            for lic in (target.get("licenses") or [])
        }
        for lic in source["licenses"]:
            k = json.dumps(lic, sort_keys=True)
            if k not in existing_lic:
                target.setdefault("licenses", []).append(lic)
                existing_lic.add(k)

    # --- hashes (union by alg) ---
    if source.get("hashes"):
        existing_algs: Dict[str, Any] = {
            h.get("alg"): h
            for h in (target.get("hashes") or [])
            if isinstance(h, dict)
        }
        for h in source["hashes"]:
            if isinstance(h, dict) and h.get("alg") not in existing_algs:
                target.setdefault("hashes", []).append(h)
                existing_algs[h.get("alg")] = h

    # --- externalReferences (union by url) ---
    if source.get("externalReferences"):
        existing_urls: set = {
            r.get("url")
            for r in (target.get("externalReferences") or [])
            if isinstance(r, dict)
        }
        for ref in source["externalReferences"]:
            if isinstance(ref, dict) and ref.get("url") not in existing_urls:
                target.setdefault("externalReferences", []).append(ref)
                existing_urls.add(ref.get("url"))


def dedup_sbom(input_path: Path, output_path: Path) -> Path:
    """
    Дедуплицировать компоненты CycloneDX SBOM по ключу PURL.

    Если PURL отсутствует, ключом служит «name@version».
    При обнаружении дублей все полезные данные (properties, cpe, hashes,
    licenses, externalReferences) объединяются в одну запись, чтобы не
    потерять сведения из разных источников (cdxgen, Clair и т.д.).
    """
    with open(input_path, encoding="utf-8") as f:
        sbom: Dict[str, Any] = json.load(f)

    components = sbom.get("components", [])
    seen: Dict[str, Dict[str, Any]] = {}
    order: list[str] = []

    for comp in components:
        purl = comp.get("purl", "")
        key = purl if purl else f"{comp.get('name', '')}@{comp.get('version', '')}"
        if key not in seen:
            seen[key] = comp
            order.append(key)
        else:
            # Дубль — перенести все полезные данные из comp в уже сохранённый
            _merge_component(seen[key], comp)

    deduped = [seen[k] for k in order]
    removed = len(components) - len(deduped)
    logging.info(
        f"[dedup] {len(components)} → {len(deduped)} компонентов (удалено {removed} дублей)"
    )

    sbom["components"] = deduped

    # Пересчитать metadata.component count если есть
    if "metadata" in sbom and isinstance(sbom["metadata"].get("component"), dict):
        pass  # не трогаем — cdxgen управляет metadata.component

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

    logging.info(f"[dedup] Записан: {output_path}")
    return output_path


def dedup_vulns(findings: List["VulnFinding"]) -> List["VulnFinding"]:
    """
    Дедуплицировать список VulnFinding по ключу «CVE-ID :: компонент».

    Если несколько сканеров обнаружили одну и ту же уязвимость в одном
    компоненте — оставляем запись с наибольшим cvss_score; при равном
    балле — первую встреченную.

    После дедупликации заполняем cvss_score == 0.0 используя лучший
    известный балл для этого CVE из других компонентов (cross-component
    propagation).
    """
    best: dict[str, "VulnFinding"] = {}

    for f in findings:
        comp_key = f.component_purl if f.component_purl else f"{f.component_name}@{f.component_version}"
        key = f"{f.cve_id}::{comp_key}"
        if key not in best or f.cvss_score > best[key].cvss_score:
            best[key] = f

    deduped = list(best.values())
    removed = len(findings) - len(deduped)
    logging.info(
        f"[dedup] {len(findings)} → {len(deduped)} уязвимостей (удалено {removed} дублей)"
    )

    # Second pass: fill cvss_score == 0 from the best score for that CVE ID
    # seen across all (possibly different) components.
    cve_best_score: dict[str, float] = {}
    for f in deduped:
        if f.cvss_score > cve_best_score.get(f.cve_id, 0.0):
            cve_best_score[f.cve_id] = f.cvss_score
    filled = 0
    for f in deduped:
        if f.cvss_score == 0.0 and cve_best_score.get(f.cve_id, 0.0) > 0.0:
            f.cvss_score = cve_best_score[f.cve_id]
            filled += 1
    if filled:
        logging.debug(f"[dedup] cvss_score заполнен для {filled} уязвимостей")

    return deduped
