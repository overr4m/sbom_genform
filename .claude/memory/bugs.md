# Bugs & Issues

## OPEN

Пока нет

## FIXED

### BUG-1: Git merge conflict маркеры в formatter.py и exporter.py

**Files**: `script/formatter.py`, `script/exporter.py`

**Description**: Файлы содержали нераскрытые маркеры git merge конфликта (`<<<<<<< HEAD`).
Две реализации существовали параллельно.

**Fix**: Оставлена HEAD-версия (рефакторинг с классами). Удалены MERGE_MSG и AUTO_MERGE.

**Status**: Fixed
