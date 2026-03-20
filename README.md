<div align="center">
<h1><a id="intro">SBOM Generator & Formatter</a></h1>
<a href="https://docs.github.com/en"><img src="https://img.shields.io/static/v1?logo=github&logoColor=fff&label=&message=Docs&color=36393f&style=flat" alt="GitHub Docs"></a>
<a href="https://daringfireball.net/projects/markdown"><img src="https://img.shields.io/static/v1?logo=markdown&logoColor=fff&label=&message=Markdown&color=36393f&style=flat" alt="Markdown"></a>
<img src="https://img.shields.io/badge/Contributor-Шмаков_И._С.-8b9aff" alt="Contributor Badge">
</div>

<div align="center">
<img src="https://img.shields.io/github/repo-size/geminishkv/sbom_genform" alt="repo size">
<img src="https://img.shields.io/github/last-commit/geminishkv/sbom_genform" alt="last commit">
<img src="https://img.shields.io/github/commit-activity/m/geminishkv/sbom_genform" alt="commit activity">
<img src="https://img.shields.io/github/issues-pr/geminishkv/sbom_genform">
<img src="https://img.shields.io/github/contributors/geminishkv/sbom_genform">
</div>

***

Инструмент для генерации, анализа и форматирования **Software Bill of Materials (SBOM)**.
Полный Python-пайплайн — без shell-скриптов.

**Что делает:**
- Генерирует SBOM из локальной директории или Git-репозитория (GitHub / GitLab)
- Сканирует уязвимости через **Trivy**, **OWASP Dependency-Check**, **Clair**
- Встраивает найденные уязвимости в SBOM (CycloneDX 1.5)
- Экспортирует читаемые отчёты: **Excel (.xlsx)**, **Word (.docx)**, **ODT (.odt)** — компоненты + уязвимости
- Подписывает итоговый SBOM (SHA-256)

***

## Структура репозитория

```
sbom_genformatter/
├── src/sbom_pipeline/          # Python-пакет (основная логика)
│   ├── cli.py                  # CLI: sbom-pipeline run | format | verify
│   ├── pipeline.py             # Оркестратор пайплайна
│   ├── generate.py             # Генерация SBOM (cdxgen / cyclonedx-py)
│   ├── dedup.py                # Дедупликация компонентов
│   ├── sign.py                 # SHA-256 подпись
│   ├── exporter.py             # Экспорт отчётов (xlsx / docx / odt)
│   ├── vuln_merger.py          # Встраивание уязвимостей в SBOM
│   ├── dependency.py           # PURL → язык + источник
│   ├── config.py               # Конфигурация из env / CLI
│   ├── constants.py            # Общие константы
│   ├── sbom_handler.py         # Чтение/запись SBOM JSON
│   ├── utils.py                # Утилиты
│   └── scanner/
│       ├── trivy.py            # Trivy (fs + sbom)
│       ├── clair.py            # Clair (container image, опционально)
│       └── depcheck.py         # OWASP Dependency-Check
├── docker/
│   ├── Dockerfile.secgensbom   # Образ для полного пайплайна
│   └── Dockerfile.formatter    # Образ только для форматирования
├── examples/
│   └── project_inject/         # Уязвимый PHP-проект для демо/тестирования
├── secgensbom/
│   └── secgensbom.yml          # GitLab CI include
├── .github/workflows/
│   └── secgensbom.yml          # GitHub Actions workflow
├── pyproject.toml              # Конфигурация пакета
└── .env.example                # Шаблон переменных окружения
```

***

## Быстрый старт

### Установка

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Запуск пайплайна

**Из локальной директории (демо-проект):**
```bash
sbom-pipeline run
# эквивалентно:
sbom-pipeline run --path examples/project_inject
```

**Из GitHub-репозитория:**
```bash
sbom-pipeline run \
  --source github \
  --url https://github.com/org/repo \
  --token ghp_...
```

**Из GitLab-репозитория:**
```bash
sbom-pipeline run \
  --source gitlab \
  --url https://gitlab.com/org/repo \
  --token glpat-...
```

**Только форматирование готовых SBOM:**
```bash
sbom-pipeline format \
  --sbom-dir secgensbom_out \
  --report-dir secgensbom_reports
```

**Проверка подписи SBOM:**
```bash
sbom-pipeline verify secgensbom_out/merged-bom-signed.json
```

```bash
sbom-pipeline run --help
```

***

## Выходные артефакты

### SBOM

| Файл | Описание |
|---|---|
| `secgensbom_out/app-bom-cdxgen.json` | Исходный SBOM (cdxgen) |
| `secgensbom_out/app-bom-dedup.json` | После дедупликации |
| `secgensbom_out/merged-bom-signed.json` | Подписанный SBOM с уязвимостями |
| `secgensbom_out/merged-bom-signed.sig` | SHA-256 контрольная сумма |
| `secgensbom_out/vulns-normalized.json` | Нормализованные уязвимости (все сканеры) |

### Отчёты сканеров

| Путь | Сканер |
|---|---|
| `secgensbom_out/trivy/trivy-fs.json` | Trivy — файловая система |
| `secgensbom_out/trivy/sbom-vulns.json` | Trivy — анализ SBOM |
| `secgensbom_out/dependency-check/` | OWASP Dependency-Check (все форматы) |
| `secgensbom_out/clair/` | Clair (если включён) |

### Читаемые отчёты

| Путь | Формат | Содержимое |
|---|---|---|
| `secgensbom_reports/excel/*.xlsx` | Excel | Лист 1: компоненты, Лист 2: уязвимости |
| `secgensbom_reports/docx/*.docx` | Word | Таблица компонентов + таблица уязвимостей |
| `secgensbom_reports/odt/*.odt` | ODT | То же самое |

***

## Docker

### Полный пайплайн

```bash
docker build -f docker/Dockerfile.secgensbom -t secgensbom-tool:latest .

# Локальный проект
docker run --rm \
  -v "$(pwd)/examples/project_inject:/app/project_inject" \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v "$(pwd)/secgensbom_reports:/app/secgensbom_reports" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e SOURCE=local \
  -e SKIP_CLAIR=true \
  secgensbom-tool:latest run

# GitHub
docker run --rm \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v "$(pwd)/secgensbom_reports:/app/secgensbom_reports" \
  -e SOURCE=github \
  -e GIT_URL=https://github.com/org/repo \
  -e GIT_TOKEN=ghp_... \
  secgensbom-tool:latest run
```

### Только форматирование

```bash
docker build -f docker/Dockerfile.formatter -t sbom-formatter:latest .

docker run --rm \
  -v "$(pwd)/secgensbom_out:/app/secgensbom_out" \
  -v "$(pwd)/secgensbom_reports:/app/secgensbom_reports" \
  sbom-formatter:latest format
```

***

## Переменные окружения

Скопируй `.env.example` → `.env` и заполни нужные значения.

| Переменная | Описание | По умолчанию |
|---|---|---|
| `SOURCE` | Источник: `local` / `github` / `gitlab` | `local` |
| `PROJECT_DIR` | Путь к проекту (local) | `examples/project_inject` |
| `GIT_URL` | URL репозитория | — |
| `GIT_TOKEN` | Токен GitHub / GitLab | — |
| `GIT_BRANCH` | Ветка (HEAD если не указана) | — |
| `OUTPUT_DIR` | Директория артефактов | `secgensbom_out` |
| `REPORTS_DIR` | Директория отчётов | `secgensbom_reports` |
| `IMAGE_NAME` | Docker-образ для Clair | — |
| `CLAIR_ENDPOINT` | Endpoint Clair-сервера | `http://clair:8080` |
| `SKIP_CLAIR` | Пропустить Clair | `true` |
| `GITHUB_TOKEN` | API-токен для определения языков зависимостей | — |

***

## Clair (опционально)

Для сканирования контейнерных образов через Clair нужен запущенный Clair + Postgres (docker-compose).

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e SKIP_CLAIR=false \
  -e IMAGE_NAME=your-app-image:tag \
  -e CLAIR_ENDPOINT=http://clair:8080 \
  secgensbom-tool:latest run
```

Если Clair недоступен — шаг автоматически пропускается, пайплайн продолжает работу.

***

## CI/CD

### GitHub Actions

Workflow запускается при пуше в `main`/`master` или вручную через **Actions → SecGenSBOM → Run workflow**.

Артефакты доступны в **Actions → Run → Artifacts**:
- `sbom-artifacts` — SBOM JSON + отчёты сканеров
- `sbom-reports` — читаемые отчёты (xlsx / docx / odt)

Секреты (`Settings → Secrets → Actions`):
- `DOCKER_USER`, `DOCKER_PASSWORD` — для публикации образа в реестр
- `GIT_TOKEN` — для сканирования приватных репозиториев

### GitLab CI

```yaml
include:
  - project: 'your-group/sbom_genformatter'
    file: 'secgensbom/secgensbom.yml'
```

Переменные CI (`Settings → CI/CD → Variables`):
- `DOCKER_REGISTRY`, `DOCKER_USER`, `DOCKER_PASSWORD` — реестр образов
- `GIT_TOKEN` — токен для приватных репо

***

## Архитектура пайплайна

```
sbom-pipeline run
    │
    ├─ 1. generate.py     → app-bom-cdxgen.json
    │     (cdxgen via npx  /  cyclonedx-py для Python  /  git clone)
    │
    ├─ 2. dedup.py        → app-bom-dedup.json
    │     (дедупликация по PURL, чистый Python)
    │
    ├─ 3. sign.py         → merged-bom-signed.json + .sig
    │     (SHA-256 в metadata.signature)
    │
    ├─ 4. scanner/
    │     ├─ trivy.py     → trivy-fs.json, sbom-vulns.json
    │     ├─ depcheck.py  → dependency-check-report.*
    │     └─ clair.py     → clair-*.json  (опционально)
    │
    ├─ 5. vuln_merger.py  → встраивает vulnerabilities[] в SBOM
    │
    └─ 6. exporter.py     → .xlsx  /  .docx  /  .odt
```

***

Copyright (c) 2025 Elijah S Shmakov

<div align="center">
<img src="docs/assets/logo.jpg" alt="Logo">
</div>
