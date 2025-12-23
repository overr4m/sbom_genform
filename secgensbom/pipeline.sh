set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env"

# Allow overriding the target project directory as the first argument.
# This is useful when this pipeline is imported by another project (CI) and
# you want outputs to be created inside that project's workspace.
if [ "$#" -ge 1 ] && [ -n "$1" ]; then
	echo "[pipeline] Overriding PROJECT_DIR with first argument: $1"
	PROJECT_DIR="$1"
	export PROJECT_DIR
	# recompute OUTPUT_DIR and REPORTS_DIR defaults if they were not explicitly set
	OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_DIR}/secgensbom_out}"
	REPORTS_DIR="${REPORTS_DIR:-${PROJECT_DIR}/secgensbom_reports}"
	export OUTPUT_DIR REPORTS_DIR
fi

echo "[pipeline] REPO_ROOT=${REPO_ROOT}"
echo "[pipeline] PROJECT_DIR=${PROJECT_DIR}"
echo "[pipeline] OUTPUT_DIR=${OUTPUT_DIR}"
# echo "[pipeline] SBOM_DIR=${SBOM_DIR}"
# echo "[pipeline] REPORTS_DIR=${REPORTS_DIR}"
# echo "[pipeline] IMAGE_NAME=${IMAGE_NAME}"

echo "[pipeline] Старт SBOM/SCA пайплайна (secgensbom)..."

/app/secgensbom/sbom_generate.sh
/app/secgensbom/sbom_merge_sign.sh
/app/secgensbom/scan_dependency_check.sh
/app/secgensbom/scan_trivy.sh
/app/secgensbom/scan_clair.sh

# Ensure output directories exist
mkdir -p "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}/dependency-check" "${OUTPUT_DIR}/trivy" "${OUTPUT_DIR}/clair"
mkdir -p "${REPORTS_DIR}"

# Generate human-readable reports (.xlsx/.odt) from signed SBOM(s)
SIGNED_SBOM="${OUTPUT_DIR}/merged-bom-signed.json"
if [ -f "${SIGNED_SBOM}" ]; then
	echo "[pipeline] Генерируем .xlsx и .odt отчёты в ${REPORTS_DIR}"
	# use the project's Python script to generate reports
	python3 "${SCRIPT_DIR}/../script/manual_formatter.py" --bom "${SIGNED_SBOM}" --out "${REPORTS_DIR}" || echo "[pipeline] Генерация отчётов завершилась с ошибкой, продолжим"
else
	echo "[pipeline] Подписанный SBOM не найден (${SIGNED_SBOM}), пропускаем генерацию .xlsx/.odt"
fi

echo "[pipeline] Пайплайн завершён."

# "${SCRIPT_DIR}/sbom_generate.sh"
# "${SCRIPT_DIR}/sbom_merge_sign.sh"
# "${SCRIPT_DIR}/scan_dependency_check.sh"
# "${SCRIPT_DIR}/scan_trivy.sh"
# "${SCRIPT_DIR}/scan_clair.sh" || echo "[pipeline] Clair шаг опционален, продолжаем."

# echo "[pipeline] Готово. Итоговый подписанный SBOM и отчёты в secgensbom_out/."
# echo "[pipeline] Итоговый SBOM: ${OUTPUT_DIR}/merged-bom-signed.json"