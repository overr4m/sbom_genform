"""
Shared constants for SBOM formatting and reporting.

Avoid duplication across modules by importing from this file.
"""

# Component types
COMPONENT_TYPE_LIBRARY = "library"

# Logging
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_FILE = "app.log"

# Extensions
JSON_EXTENSION = ".json"
EXCEL_EXTENSION = ".xlsx"
ODT_EXTENSION = ".odt"

# Directory names
EXCEL_DIR = "excel"
ODT_DIR = "odt"
SBOM_OUT_DIR = "secgensbom_out"
REPORTS_DIR = "secgensbom_reports"
