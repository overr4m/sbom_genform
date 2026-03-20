# Project: sbom_genformatter

## Purpose

Генерация, обработка, форматирование и цифровая подпись Software Bill of Materials (SBOM).
Целевой формат: CycloneDX 1.5 JSON.

## Stack

- Python 3.12 (core logic)
- Bash (pipeline orchestration)
- pandas + openpyxl (Excel export)
- odfpy (ODT export)
- cryptography (RSA-SHA256 signing)
- packageurl-python (PURL parsing)
- cdxgen / Node.js 20 (SBOM generation)
- Trivy, OWASP Dependency-Check, Clair (vulnerability scanning)
- Docker (containerization)
- GitHub Actions (CI/CD)

## Key Directories

```text
script/            — Python модули (formatter, exporter, signer, dependency, utils)
secgensbom/        — Bash скрипты пайплайна + config.env + GitLab CI
.github/workflows/ — GitHub Actions
resolve/           — SCA.Dockerfile (multi-tool SCA container)
config/            — config.yaml
sbom/              — тестовые SBOM файлы (git/ + images/)
reports/           — сгенерированные примеры отчётов
project_inject/    — уязвимое PHP приложение для тестирования
```

## Core Python Modules

- `formatter.py` — точка входа; пакетная обработка SBOM → Excel/ODT (FormatterConfig, SbomFormatter)
- `manual_formatter.py` — CLI с PURL-обогащением и RSA-подписью
- `sbom_handler.py` — поиск файлов и парсинг JSON (SbomHandler)
- `exporter.py` — генерация Excel/ODT отчётов + подпись (Exporter)
- `dependency.py` — модель зависимости + PURL парсинг; фабрика PackageProcessor
- `sbom_signer.py` — RSA-SHA256 подпись/верификация (SbomSigner)
- `utils.py` — clean_git_url()
- `constants.py` — общие константы

## Entry Points

```bash
# Авто-форматтер
python script/formatter.py --sbom-dir ./sbom --report-dir ./reports

# Ручной с подписью
python script/manual_formatter.py --bom sbom.json --out reports --sign --private-key keys/private.pem

# Полный пайплайн
./secgensbom/pipeline.sh [PROJECT_DIR]
```

## Output Formats

- Excel (.xlsx): 6 колонок на русском — №, Наименование, Версия, Язык, Принадлежность, Адрес веб-ресурса
- ODT (.odt): таблица с теми же колонками, стилизованные заголовки
- Подписи (.sig): JSON с RSA-SHA256, SHA256-хэш, timestamp, fingerprint ключа

## Known Issues

- `formatter.py` и `exporter.py` содержат нераскрытые git merge conflict маркеры (<<<<<<< HEAD)
- `project_inject/` — уязвимое PHP приложение, не часть основного инструмента
- Полный пайплайн требует Node.js 20+ (cdxgen) и Docker socket для DIP

## User Preferences

- Коммиты делает сам пользователь, Claude не коммитит
- Язык общения: русский

## Known Bugs

See `.claude/memory/bugs.md`
