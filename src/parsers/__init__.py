# Version String
PROG_NAME = 'Static Analysis Results Parser'
VERSION = '1.3.2'

# Control Flag Names
FLAG_CATEGORY_MAPPING = 'Category Mappings'
FLAG_OVERRIDE_CWE = 'Override CWE'
FLAG_OVERRIDE_CONFIDENCE = 'Override Confidence'
FLAG_FORCE_EXPORT_CSV = 'Force Export CSV'

# Set GUI mode to enable/disable messageboxes
GUI_MODE = False

# List of scanners for the GUI dropdown
LIST_OF_SCANNERS = ["Checkmarx", "Coverity", "CPPCheck", "ESLint", "Fortify", "GNAT SAS", "NVD CVEs", "OWASP Dependency Check", "Pragmatic", "Pylint", "SARP", "Semgrep", "Sigasi", "SRM"]

# Empty overrides for fallback
EMPTY_OVERRIDES = "{\"sarp\":{},\"checkmarx\":{},\"coverity\":{},\"cppcheck\":{},\"eslint\":{},\"fortify\":{},\"gnatsas\":{},\"manual_cve\":{},\"owasp_depcheck\":{},\"pragmatic\":{},\"pylint\":{},\"semgrep\":{},\"sigasi\":{},\"srm\":{}}\n"

# Keywords for scanners
aio_keywords = ['aio', 'allinone', 'all-in-one', 'allinoneparser', 'all-in-oneparser', 'sarp', 'saresultsparser', 'saresultparser', 'sarparser', 'sarparse', 'staticanalysisresultsparser']
cppcheck_keywords = ['cppcheck']
coverity_keywords = ['coverity']
depcheck_keywords = ['dependencycheck', 'depcheck', 'owasp', 'owaspdependencycheck', 'owaspdepcheck']
eslint_keywords = ['eslint']
fortify_keywords = ['fortify', 'fortifysca']
gnatsas_keywords = ['gnatsas', 'codepeer']
manualcve_keywords = ['cve', 'manualcve', 'manualnvd', 'nvd']
pragmatic_keywords = ['pragmatic']
pylint_keywords = ['pylint']
sigasi_keywords = ['sigasi', 'vhdl', 'verilog', 'systemverilog']
semgrep_keywords = ['semgrep']
srm_keywords = ['srm', 'softwareriskmanager', 'codedx']
xmarx_keywords = ['checkmarx', 'xmarx']
scanner_keywords = aio_keywords + cppcheck_keywords + coverity_keywords + depcheck_keywords + eslint_keywords + fortify_keywords + gnatsas_keywords + manualcve_keywords + pragmatic_keywords + pylint_keywords + semgrep_keywords + sigasi_keywords + srm_keywords + xmarx_keywords
nopathoverridescanners_keywords = aio_keywords + manualcve_keywords

# Valid extensions
valid_extensions = ['.fpr', '.csv', '.xml', '.json', '.xlsx']

# Important Paths (overwritten by parse.py)
EXE_ROOT_DIR = '.'
LOGS_DIR = 'logs'
CONFIG_DIR = 'config'

# CWE Category Mappings
cwe_categories = {}

# Choose specific items to import when using "from parsers import *"
__all__ = ['FLAG_CATEGORY_MAPPING', 'FLAG_OVERRIDE_CWE', 'FLAG_OVERRIDE_CONFIDENCE', 'FLAG_FORCE_EXPORT_CSV', 'aio', 'checkmarx', 'coverity', 'cppcheck', 'owasp_depcheck', 'eslint', 'gnatsas', 'fortify', 'manual_cve', 'pragmatic', 'pylint', 'semgrep', 'sigasi', 'srm']
