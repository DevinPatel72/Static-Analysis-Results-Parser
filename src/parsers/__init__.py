# Version String
PROG_NAME = 'Static Analysis Results Parser'
PROG_NAME_ABBR = 'SARP'
VERSION = '2.9.0'

# Project Info
PROJ_NAME = ""
PROJ_VERSION = ""

# Control Flag Names
FLAG_CATEGORY_MAPPING = 'Category Mappings'
FLAG_PREFLIGHT_RULES = 'Preflight Rules'
FLAG_DEFAULT_PREFLIGHT_RULES = 'Default Preflight Rules'
FLAG_DUPE_SCAN_CONSOLIDATION = 'Duplicate Scanner Consolidation'
FLAG_SARIF_STITCH_PROPERTIES = 'SARIF STITCH Properties'

# Set GUI mode to enable/disable messageboxes
GUI_MODE = False

# GUI Root
gui_root = None

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

# Updater globals
REPO_BASE_URL = "https://api.github.com/repos/DevinPatel72/Static-Analysis-Results-Parser"

# Choose specific items to import when using "from parsers import *"
__all__ = ['PROG_NAME', 'PROG_NAME_ABBR', 'VERSION', 'aio', 'checkmarx', 'coverity', 'cppcheck', 'owasp_depcheck', 'eslint', 'gnatsas', 'fortify', 'manual_cve', 'pragmatic', 'pylint', 'semgrep', 'sigasi', 'srm']
