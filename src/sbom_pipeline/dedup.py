"""Дедупликация компонентов SBOM — чистый Python."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict


def dedup_sbom(input_path: Path, output_path: Path) -> Path:
    """
    Дедуплицировать компоненты CycloneDX SBOM по ключу PURL.

    Если PURL отсутствует, ключом служит «name@version».
    """
    with open(input_path, encoding="utf-8") as f:
        sbom: Dict[str, Any] = json.load(f)

    components = sbom.get("components", [])
    seen: set[str] = set()
    deduped: list[Dict[str, Any]] = []

    for comp in components:
        purl = comp.get("purl", "")
        key = purl if purl else f"{comp.get('name', '')}@{comp.get('version', '')}"
        if key not in seen:
            seen.add(key)
            deduped.append(comp)

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
