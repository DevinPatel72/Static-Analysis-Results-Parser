# Version String
PROG_NAME = 'Static Analysis Results Parser'
PROG_NAME_ABBR = 'SARP'
VERSION = '2.7.0'

# Project Info
PROJ_NAME = ""
PROJ_VERSION = ""

# Control Flag Names
FLAG_CATEGORY_MAPPING = 'Category Mappings'
FLAG_PREFLIGHT_RULES = 'Preflight Rules'
FLAG_DEFAULT_PREFLIGHT_RULES = 'Default Preflight Rules'
FLAG_DUPE_SCAN_CONSOLIDATION = 'Duplicate Scanner Consolidation'
FLAG_SARIF_CVSS_METADATA = 'SARIF STITCH Properties'

# Set GUI mode to enable/disable messageboxes
GUI_MODE = False

# Preflight Rules
prules = []
default_prules = []

# Control Flags
control_flags = []

# CWE Category Mappings
cwe_categories = {}

# Important Paths (overwritten by parse.py)
EXE_ROOT_DIR = '.'
LOGS_DIR = 'logs'
LOGFILE = 'temp.log'
CONFIG_DIR = 'config'
MAPPINGS_DIR = 'mappings'
PREFLIGHT_DIR = 'preflight'
INPUTS_DIR = 'inputs'
INPUTS_PATH = ''

# Multithreading globals
progress_queue = None

# Choose specific items to import when using "from parsers import *"
__all__ = ['PROG_NAME', 'PROG_NAME_ABBR', 'VERSION', 'FLAG_CATEGORY_MAPPING', 'FLAG_PREFLIGHT_RULES', 'FLAG_DEFAULT_PREFLIGHT_RULES', 'FLAG_DUPE_SCAN_CONSOLIDATION', 'aio', 'checkmarx', 'coverity', 'cppcheck', 'owasp_depcheck', 'eslint', 'gnatsas', 'fortify', 'manual_cve', 'pragmatic', 'pylint', 'semgrep', 'sigasi', 'srm']
