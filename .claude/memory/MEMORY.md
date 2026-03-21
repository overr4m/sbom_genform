# Project: open-source_toolchain_map

## Purpose
MkDocs-based static documentation site — карта инструментов AppSec/DevSecOps.
Deployed to GitHub Pages: https://geminishkv.github.io/oss_toolchainmap/

## Key Files
- `main.py` — MkDocs macros entry point (`define_env`), used by `mkdocs-macros-plugin`
- `mkdocs.yml` — конфигурация сайта + `extra.table_config` с маппингом категорий → YAML-файлов
- `scripts/table_data.py` — загрузка и нормализация YAML-данных для таблицы
- `scripts/table_render.py` — рендер статической HTML-таблицы (для PDF)
- `scripts/render_tools_popups_from_table.py` — интерактивная таблица с попапами (для сайта)
- `scripts/build_search_data.py` — генерация `docs/assets/search/tools.json`
- `scripts/export_tools_pdf.py` — экспорт PDF через weasyprint
- `scripts/__init__.py` — CLI роутер (`build-search`, `export-pdf`)
- `requirements.txt` — Python 3.11, mkdocs, weasyprint, ruff, mypy, bandit, safety
- `mypy.ini` — strict mypy config, python_version=3.11
- `.github/workflows/ci.yml` — lint → layout lint → audit → security → build → deploy
- `.github/workflows/release-from-notes.yml` — релиз по тегу v*.*.*

## Architecture
```
mkdocs.yml (extra.table_config)
    └─> main.py (define_env macros)
         ├─> table_data.py (load YAML → normalize)
         ├─> table_render.py (HTML table static)
         └─> render_tools_popups_from_table.py (HTML table interactive)

scripts/build_search_data.py ─> docs/assets/search/tools.json
scripts/export_tools_pdf.py  ─> docs/pdf_table/tools-map.pdf
```

## Tool YAML Structure
```yaml
Tools:
  - name: ToolName
    meta:
      description: "..."
      link_URL: "..."
      ver_edition: "..."
      FSTEK_cert: "Нет"
      RUS_access: "Доступен"
      report_formats: [...]
      detect_methods: [...]
      OSS: "true"             # string, not bool
      division: "AppSec"
      type: "SAST"
      class: "Статический анализатор"
      vendor: "..."
      lic: "..."
```

## Tool Categories (table_config)
- AppSec → SAST, Attack Surface Analysis, IAST, SCA/OSA, SBOM, BCA, DAST, MAST, RASP, API
- codecoverage, ASPM, Container Security, Secrets Management, MLSecOps

## TODO: создать scripts/generate_sitemap.py

Шаг в ci.yml уже есть (строка "Generate sitemap.xml"), скрипта пока нет.
Нужен для SEO — генерирует sitemap.xml из собранного сайта.
Когда скрипт появится — CI подхватит автоматически.

## User Preferences
- Коммиты делает сам пользователь, Claude не коммитит
- Язык общения: русский
- Attribution отключён (commit/pr пустые строки в ~/.claude/settings.json)

## Known Bugs
See `.claude/memory/bugs.md`

## Ветки репозитория
See `.claude/memory/project_branches.md`

`secgensbom.yml` — только для ветки `securitycheck`, не трогать триггеры.

---

## Стандарты для всех проектов пользователя

### README Standard

See `.claude/memory/readme_standard.md`

Шаблон README.md отработан на `sbom_genformatter`. Применять ко всем AppSec/DevSecOps репозиториям.

### CLI Standard

See `.claude/memory/cli_standard.md`

CLI-паттерн (typer + rich) отработан на `sbom_genformatter/src/sbom_pipeline/cli.py`. Переиспользовать в новых инструментах.
