"""
CLI точка входа: sbom-pipeline

Подкоманды:
  run     — полный пайплайн (генерация → сканирование → отчёты)
  format  — только форматирование готовых SBOM → xlsx/docx/odt
  verify  — проверить SHA-256 подпись SBOM
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .config import PipelineConfig
from .pipeline import run as pipeline_run, format_sboms
from .sign import verify_sbom
from .utils import setup_logging

app = typer.Typer(
    name="sbom-pipeline",
    help="SBOM Generator & Formatter — pure Python, no shell.",
    add_completion=False,
)
console = Console()


# ------------------------------------------------------------------
# run — полный пайплайн
# ------------------------------------------------------------------

@app.command("run", help="Полный пайплайн: генерация SBOM → сканирование → отчёты.")
def cmd_run(
    source: str = typer.Option(
        "local",
        "--source", "-s",
        help="Источник: local | github | gitlab",
        envvar="SOURCE",
    ),
    path: Optional[Path] = typer.Option(
        None,
        "--path",
        help="Путь к директории проекта (для source=local, по умолчанию: project_inject/)",
        envvar="PROJECT_DIR",
    ),
    url: Optional[str] = typer.Option(
        None,
        "--url",
        help="URL репозитория GitHub/GitLab",
        envvar="GIT_URL",
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        help="Токен доступа GitHub (ghp_...) или GitLab (glpat-...)",
        envvar="GIT_TOKEN",
    ),
    branch: Optional[str] = typer.Option(
        None,
        "--branch",
        help="Ветка репозитория (по умолчанию HEAD)",
        envvar="GIT_BRANCH",
    ),
    output_dir: Path = typer.Option(
        Path("secgensbom_out"),
        "--output-dir", "-o",
        help="Директория артефактов пайплайна",
        envvar="OUTPUT_DIR",
    ),
    reports_dir: Path = typer.Option(
        Path("secgensbom_reports"),
        "--reports-dir",
        help="Директория отчётов",
        envvar="REPORTS_DIR",
    ),
    image_name: Optional[str] = typer.Option(
        None,
        "--image",
        help="Docker-образ для сканирования Clair",
        envvar="IMAGE_NAME",
    ),
    clair_endpoint: str = typer.Option(
        "http://clair:8080",
        "--clair-endpoint",
        envvar="CLAIR_ENDPOINT",
    ),
    no_clair: bool = typer.Option(
        True,
        "--no-clair/--clair",
        help="Пропустить шаг Clair (по умолчанию: пропускать)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    setup_logging(verbose)

    cfg = PipelineConfig.from_env()
    # Перекрыть значениями из CLI
    cfg.source = source
    if path:
        cfg.project_dir = path
    if url:
        cfg.git_url = url
    if token:
        cfg.git_token = token
    if branch:
        cfg.git_branch = branch
    cfg.output_dir = output_dir
    cfg.reports_dir = reports_dir
    cfg.image_name = image_name or cfg.image_name
    cfg.clair_endpoint = clair_endpoint
    cfg.skip_clair = no_clair
    # Пересчитать производные пути
    cfg.__post_init__()

    try:
        pipeline_run(cfg)
        console.print("[green]✓ Пайплайн завершён успешно[/green]")
    except Exception as e:
        console.print(f"[red]✗ Ошибка: {e}[/red]")
        raise typer.Exit(code=1)


# ------------------------------------------------------------------
# format — только форматирование
# ------------------------------------------------------------------

@app.command("format", help="Форматировать SBOM JSON → xlsx / docx / odt.")
def cmd_format(
    sbom_dir: Path = typer.Option(
        Path("secgensbom_out"),
        "--sbom-dir",
        help="Директория с SBOM JSON файлами",
        envvar="OUTPUT_DIR",
    ),
    report_dir: Path = typer.Option(
        Path("secgensbom_reports"),
        "--report-dir",
        help="Директория для отчётов",
        envvar="REPORTS_DIR",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    setup_logging(verbose)
    try:
        format_sboms(sbom_dir, report_dir)
        console.print("[green]✓ Форматирование завершено[/green]")
    except Exception as e:
        console.print(f"[red]✗ Ошибка: {e}[/red]")
        raise typer.Exit(code=1)


# ------------------------------------------------------------------
# verify — проверка подписи
# ------------------------------------------------------------------

@app.command("verify", help="Проверить SHA-256 подпись SBOM.")
def cmd_verify(
    sbom: Path = typer.Argument(..., help="Путь к SBOM JSON файлу"),
) -> None:
    setup_logging()
    ok = verify_sbom(sbom)
    if ok:
        console.print(f"[green]✓ Подпись верифицирована: {sbom}[/green]")
    else:
        console.print(f"[red]✗ Подпись не прошла проверку: {sbom}[/red]")
        raise typer.Exit(code=1)


# ------------------------------------------------------------------
# Точка входа
# ------------------------------------------------------------------

def main() -> None:
    app()


if __name__ == "__main__":
    main()
