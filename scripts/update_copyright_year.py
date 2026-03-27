import os
import re
from datetime import datetime


def update_copyright_year(directory, excluded_directories=None):
    # Получаем текущий и прошлый год
    current_year = datetime.now().year
    previous_year = current_year - 1

    # Регулярное выражение: ищем 'copyright', любой текст после него и прошлый год
    # Например: "Copyright (c) 2025" -> "Copyright (c) 2026"
    pattern = re.compile(rf'(copyright.*?){previous_year}', re.IGNORECASE)
    replacement = rf'\g<1>{current_year}'

    for root, dirs, files in os.walk(directory):
        # Модифицируем dirs in-place, чтобы os.walk не заходил в исключенные папки
        dirs[:] = [d for d in dirs if d not in excluded_dirs]

        for file in files:
            # Пропускаем скрытые файлы
            if file.startswith('.'):
                continue

            file_path = os.path.join(root, file)

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                if pattern.search(content):
                    new_content = pattern.sub(replacement, content)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"✅ Обновлено: {file_path}")

            except (UnicodeDecodeError, PermissionError):
                continue
            except Exception as e:
                print(f"❌ Ошибка в {file_path}: {e}")


if __name__ == "__main__":
    # Укажите путь к папке (по умолчанию — текущая директория '.')
    target_directory = "."
    excluded_directories = ["venv, tools"]
    update_copyright_year(target_directory, excluded_directories)