"""Генерация SBOM из локальной директории или Git-репозитория."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .constants import APP_BOM_FILE, CYCLONEDX_SPEC_VERSION


def _detect_project_type(project_dir: Path) -> str:
    """Определить тип проекта по манифестам."""
    checks: list[tuple[str, str]] = [
        ("requirements.txt", "python"),
        ("pyproject.toml", "python"),
        ("Pipfile", "python"),
        ("poetry.lock", "python"),
        ("package.json", "nodejs"),
        ("pom.xml", "java"),
        ("build.gradle", "java"),
        ("composer.json", "php"),
        ("go.mod", "go"),
        ("Cargo.toml", "rust"),
    ]
    for filename, lang in checks:
        if (project_dir / filename).exists():
            return lang
    return "unknown"


def generate_from_dir(project_dir: Path, output_file: Path) -> Path:
    """
    Сгенерировать SBOM из локальной директории.

    Стратегия:
    1. Для Python-проектов — cyclonedx-py (Python-нативный).
    2. Для остальных — cdxgen через npx (поддерживает PHP, Java, Go и т.д.).
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    project_type = _detect_project_type(project_dir)
    logging.info(f"[generate] Тип проекта: {project_type} в {project_dir}")

    if project_type == "python" and shutil.which("cyclonedx-py"):
        result = _generate_python_sbom(project_dir, output_file)
        if result:
            return result
        logging.warning("[generate] cyclonedx-py не сработал, fallback → cdxgen")

    return _generate_cdxgen_sbom(project_dir, output_file)


def _generate_python_sbom(project_dir: Path, output_file: Path) -> Optional[Path]:
    """Использовать cyclonedx-py для Python-проектов."""
    for req_file in ("requirements.txt", "Pipfile", "poetry.lock"):
        req_path = project_dir / req_file
        if not req_path.exists():
            continue
        cmd = [
            "cyclonedx-py",
            "requirements",
            str(req_path),
            "--output-format", "JSON",
            "--output-file", str(output_file),
        ]
        logging.info(f"[generate] cyclonedx-py: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f"[generate] SBOM → {output_file}")
            return output_file
        logging.warning(f"[generate] cyclonedx-py stderr: {result.stderr[:300]}")
    return None


def _generate_cdxgen_sbom(project_dir: Path, output_file: Path) -> Path:
    """Использовать cdxgen (npx) — универсальный генератор."""
    npx = shutil.which("npx")
    if not npx:
        raise RuntimeError(
            "npx не найден. Установите Node.js и npm, либо используйте Docker-образ."
        )

    cmd = [
        npx,
        "--yes",
        "@cyclonedx/cdxgen",
        "--spec-version", CYCLONEDX_SPEC_VERSION,
        "--no-bom-url",
        "--output", str(output_file),
        str(project_dir),
    ]
    logging.info(f"[generate] cdxgen: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"cdxgen завершился с ошибкой:\n{result.stderr}")

    logging.info(f"[generate] SBOM → {output_file}")
    return output_file


def generate_from_git(
    url: str,
    output_file: Path,
    token: Optional[str] = None,
    branch: Optional[str] = None,
) -> Path:
    """
    Клонировать Git-репозиторий (GitHub / GitLab) и сгенерировать SBOM.

    Токен встраивается в URL как oauth2-заголовок, что поддерживается
    обоими платформами (GitHub: ghp_... / GitLab: glpat-...).
    """
    import git as gitpy  # gitpython — импортируем локально

    from urllib.parse import urlparse, urlunparse

    clone_url = url
    if token:
        parsed = urlparse(url)
        netloc = f"oauth2:{token}@{parsed.netloc}"
        clone_url = urlunparse(parsed._replace(netloc=netloc))

    with tempfile.TemporaryDirectory(prefix="sbom_clone_") as tmpdir:
        clone_dir = Path(tmpdir) / "repo"
        logging.info(f"[generate] Клонирование {url} ...")
        kwargs: dict = {"depth": 1}
        if branch:
            kwargs["branch"] = branch
        gitpy.Repo.clone_from(clone_url, clone_dir, **kwargs)
        logging.info(f"[generate] Клонировано в {clone_dir}")
        return generate_from_dir(clone_dir, output_file)
