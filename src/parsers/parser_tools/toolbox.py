# toolbox.py

import os
import logging
import json
import importlib
from enum import Enum
from tkinter import messagebox
from .progressbar import progress_bar,SPACE
import parsers

__excel_enabled = False
try:
    import openpyxl
    __excel_enabled = True
except (ImportError, ModuleNotFoundError):
    __excel_enabled = False


logger = logging.getLogger(__name__)

LARGE_FILE_THRESHOLD_MB = 40
FILE_SIZE_WARNED_ONCE = False
FORTIFY_FILE_WARNED_ONCE = False

class InputDictKeys(Enum):
    PATH = 'path'
    SCANNER = 'scanner'
    PREPEND = 'prepend'
    REMOVE = 'remove'
    OUTFILE = 'outfile'
    
    @classmethod
    def inputs(cls):
        return [cls.PATH.value, cls.SCANNER.value, cls.PREPEND.value, cls.REMOVE.value]

class InputConfigFlags(Enum):
    OVERRIDE_VULN_MAPPING = (parsers.FLAG_CATEGORY_MAPPING, True, "If enabled, this will append \":CATEGORY\", \":DISCOURAGED\", etc. to the end of CWE numbers.", 'OutfileFlagsGUI')
    PREFLIGHT_RULES = (parsers.FLAG_PREFLIGHT_RULES, True, "If enabled, this will change final output values according to user-defined rules.", 'OutfileFlagsGUI')
    DEFAULT_PREFLIGHT_RULES = (parsers.FLAG_DEFAULT_PREFLIGHT_RULES, True, "If enabled, changes final output values according to a default profile of rules. Only activated if \"Preflight Rules\" flag is also true.", 'RuleBuilderGUI')
    DUPE_SCAN_CONSOLIDATION = (parsers.FLAG_DUPE_SCAN_CONSOLIDATION, False, "If enabled, this will identify duplicate findings for results from identical scanners. This option might significantly increase completion time, so it is recommended to leave it disabled unless there is a need for deduplication of findings from the same scanner.", 'OutfileFlagsGUI')
    SARIF_STITCH_PROPERTIES = (parsers.FLAG_SARIF_STITCH_PROPERTIES, False, "By default, SARIF format will output without CVSS properties such as Confidence, Exploit Maturity, Environmental Metrics, etc. To include these properties, set this flag to true.", 'OutfileFlagsGUI')

    def __init__(self, flag, default, description, module_visibility):
        self.flag = flag
        self.default = default
        self.description = description
        self.module_visibility = module_visibility
    
    @classmethod
    def all_flags(cls):
        return [f.flag for f in cls]

class InputSchemaKeys(Enum):
    SCHEMA = "$schema"
    PROJ_NAME = "project_name"
    PROJ_VERSION = "project_version"
    MAIN = "main"
    OUTFILE = "outfile"
    FLAGS = "flags"

class Fieldnames(Enum):
    SCORING_BASIS = 'Scoring Basis'
    CONFIDENCE = 'Confidence'
    MATURITY = 'Exploit Maturity'
    MITIGATION = 'Environmental Metrics'
    VALIDATOR_COMMENT = 'Validator Justification'
    PROPOSED_MITIGATION = 'Proposed Mitigation'
    ID = 'ID'
    PATH = 'Path'
    LINE = 'Line'
    TYPE = 'Type'
    MESSAGE = 'Message'
    TRACE = 'Trace'
    SYMBOL = 'Symbol'
    TOOL_CWE = 'Tool CWE'
    TOOL = 'Tool'
    SCANNER = 'Scanner'
    LANGUAGE = 'Language'
    SEVERITY = 'Tool Severity'
    
    HEADERS = [SCORING_BASIS, CONFIDENCE, MATURITY, MITIGATION, PROPOSED_MITIGATION, VALIDATOR_COMMENT, ID, PATH, LINE, TYPE, MESSAGE, TRACE, SYMBOL, TOOL_CWE, TOOL, SCANNER, LANGUAGE, SEVERITY]
    EDITABLE_HEADERS = [SCORING_BASIS, CONFIDENCE, MATURITY, MITIGATION, PROPOSED_MITIGATION, VALIDATOR_COMMENT]
    DEFAULT_CONF = 'To Verify'
    DUPLICATE_CONF = 'DUPLICATE'
    DEFAULT_MATURITY = 'Unreported'
    DEFAULT_MITIGATION = ''
    MODIFIED_MITIGATION_NONE = '/MVC:N/MVI:N/MVA:N'
    
    def __str__(self):
        return self.value

# Identity dict for sarif inputs
_sarif_mapping_identity = {"error": "error", "warning": "warning", "note": "note", "none": "none"}

class Scanners(Enum):
    # ( NAME,
    #   KEYWORDS,
    #   VALID_EXTENSIONS,
    #   SEVERITY_MAP {"tool_severity": "sarif_level", ...},
    #   parsers_module )
    
    # Valid SARIF severity strings ('level'): ["error", "warning", "note", "none"]
    SARP = (parsers.PROG_NAME_ABBR,
            ['aio', 'allinone', 'all-in-one', 'allinoneparser', 'all-in-oneparser', 'sarp', 'saresultsparser', 'saresultparser', 'sarparser', 'sarparse', 'staticanalysisresultsparser'],
            ('.xlsx', '.csv', '.json', '.sarif'),
            _sarif_mapping_identity,
            'parsers.aio')
    SARIF = ('SARIF',
            ['sarif'],
            ('.sarif', '.json'),
            _sarif_mapping_identity,
            'parsers.sarif')
    CHECKMARX = ('Checkmarx',
                 ['checkmarx', 'xmarx'],
                 ('.xml', '.csv'),
                 {
                    "critical": "error",
                    "high": "error",
                    "medium": "warning",
                    "low": "note",
                    "information": "note"
                 },
                 'parsers.checkmarx')
    CPPCHECK = ('CPPCheck',
                ['cppcheck'],
                ('.xml',),
                {
                    "error": "error",
                    "warning": "warning",
                    "style": "note",
                    "performance": "note",
                    "portability": "note",
                    "information": "note",
                    "debug": "none"
                },
                'parsers.cppcheck')
    COVERITY = ('Coverity',
                ['coverity'],
                ('.json',),
                {
                    "high": "error",
                    "medium": "warning",
                    "low": "note",
                    "audit": "note"
                },
                'parsers.coverity')
    ESLINT = ('ESLint',
                ['eslint'],
                ('.json',),
                {
                    "0": "note",
                    "off": "note",
                    "1": "warning",
                    "2": "error"
                },
                'parsers.eslint')
    FLAWFINDER = ('Flawfinder',
                ['flawfinder'],
                ('.csv',),
                {
                    "0": "note",
                    "1": "warning",
                    "2": "warning",
                    "3": "error",
                    "4": "error",
                    "5": "error",
                    "0 (very little risk)": "note",
                    "1 (little risk)": "warning",
                    "2 (medium risk)": "warning",
                    "3 (high risk)": "error",
                    "4 (very high risk)": "error",
                    "5 (great risk)": "error"
                },
                'parsers.flawfinder')
    FORTIFY = ('Fortify',
                ['fortify', 'fortifysca'],
                ('.fpr',),
                {
                    "0.0": "note",
                    "1.0": "note",
                    "2.0": "note",
                    "3.0": "warning",
                    "4.0": "error",
                    "5.0": "error",
                    "0.0 (info)": "note",
                    "1.0 (info)": "note",
                    "2.0 (low)": "note",
                    "3.0 (medium)": "warning",
                    "4.0 (high)": "error",
                    "5.0 (critical)": "error"
                },
                'parsers.fortify')
    GNATSAS = ('GNAT SAS',
                ['gnatsas', 'codepeer'],
                ('.sarif', '.json', '.csv'),
                _sarif_mapping_identity | {
                    "high": "error",
                    "medium": "warning",
                    "low": "note",
                    "info": "note"
                },
                'parsers.gnatsas')
    NVD_CVE = ('NVD CVE',
               ['cve', 'manualcve', 'manualnvd', 'nvd'],
               ('.csv',),
               _sarif_mapping_identity,
               'parsers.manual_cve')
    DEP_CHECK = ('OWASP Dependency Check',
                ['dependencycheck', 'depcheck', 'owasp', 'owaspdependencycheck', 'owaspdepcheck'],
                ('.json', '.csv'),
                {
                    "none": "none",
                    "low": "note",
                    "medium": "warning",
                    "high": "error",
                    "critical": "error"
                },
                'parsers.owasp_depcheck')
    PRAGMATIC = ('Pragmatic',
                ['pragmatic'],
                ('.csv',),
                {}, # Leave empty
                'parsers.pragmatic')
    PYLINT = ('Pylint',
                ['pylint'],
                ('.json',),
                {
                    "fatal": "error",
                    "error": "error",
                    "warning": "warning",
                    "refactor": "note",
                    "convention": "note",
                    "info": "note"
                },
                'parsers.pylint')
    SEMGREP = ('Semgrep',
                ['semgrep'],
                ('.json', '.csv'),
                {
                    "low": "note",
                    "medium": "warning",
                    "high": "error",
                    "critical": "error",
                    "info": "note",
                    "warning": "warning",
                    "error": "error"
                },
                'parsers.semgrep')
    SIGASI = ('Sigasi',
              ['sigasi', 'vhdl', 'verilog', 'systemverilog'],
              ('.json',),
              {
                  "note": "note",
                  "warning": "warning",
                  "error": "error",
                  "failure": "note"
              },
              'parsers.sigasi')
    SPOTBUGS = ('SpotBugs',
              ['spotbugs', 'findbugs'],
              ('.sarif', '.xml'),
              _sarif_mapping_identity | {
                  "of concern": "warning",
                  "troubling": "warning",
                  "scary": "error",
                  "scariest": "error"
              },
              'parsers.spotbugs')
    SRM = ('Software Risk Manager',
           ['srm', 'softwareriskmanager', 'codedx'],
           ('.xml', '.csv'),
           {}, # Leave empty
           'parsers.srm')

    def __init__(self, sname, keywords, valid_ext, severity_map, module):
        self.sname = sname
        self.keywords = keywords
        self.valid_ext = valid_ext
        self.severity_map = severity_map
        self.module = module
    
    @classmethod
    def all_names(cls):
        return [scanner.sname for scanner in cls]
    
    @classmethod
    def all_keywords(cls):
        return set([keyword
                    for scanner in cls
                    for keyword in scanner.keywords])
    
    @classmethod
    def all_valid_ext(cls):
        return set([valid_ext
                    for scanner in cls
                    for valid_ext in scanner.valid_ext])

def validate_path_and_scanner(fpath, scanner):
    global __excel_enabled, FILE_SIZE_WARNED_ONCE, FORTIFY_FILE_WARNED_ONCE
    scan_match = scanner.lower().replace(' ', '')
    
    if not any(s in scan_match for s in Scanners.all_keywords()):
        return "{} does not currently support input from {}. A list of acceptable scanners and their file types is in the readme.txt file.".format(parsers.PROG_NAME, scanner)
    
    # Alert for large file size for CLI
    if not FILE_SIZE_WARNED_ONCE and os.path.isfile(fpath) and get_file_size_mb(fpath) > LARGE_FILE_THRESHOLD_MB:
        FILE_SIZE_WARNED_ONCE = True
        if parsers.GUI_MODE:
            _end = f" If {parsers.PROG_NAME_ABBR} takes too long to complete, stop execution at the loading screen and immediately rerun using the CLI executable."
        else:
            _end = ""
        console(f"A large input file has been detected. Processing times may be fairly long, so {parsers.PROG_NAME_ABBR} will appear to freeze or hang." + _end, title='Large File Detected', type='warning', orig_name=__name__)
    
    # AIO parser inputs
    elif any(s in scan_match for s in Scanners.SARP.keywords) and os.path.isfile(fpath):
        # Check file extension
        ext = os.path.splitext(fpath)[1]
        if ext not in Scanners.SARP.valid_ext:
            return f"File extension \'{ext}\' not supported for {scanner} input"
        
        # Diverge depending on .xlsx, .json, .sarif, or .csv
        if __excel_enabled and ext == '.xlsx':
            # Excel - Extract headers
            workbook = openpyxl.load_workbook(fpath)
            sheet = workbook[workbook.sheetnames[0]]
            headers = [cell.value for cell in sheet[1]]
        # SARIF format
        elif ext == '.json' or ext == '.sarif':
            headers = [] # Unable to read headers since they are different in a SARIF file
        else:
            # CSV - Extract headers
            with open(fpath, 'r', encoding='utf-8-sig') as f:
                headers = f.readline().strip().split(',')
        
        # Check headers
        if len(headers) > 0 and not all(h in Fieldnames.HEADERS.value for h in headers):
            # Doesn't match any expected headers
            return f"Input for scanner {scanner} does not match expected fieldnames.\n    {headers}\n  Ensure all of the headers match the following format:\n    {Fieldnames.HEADERS.value}"

    # Fortify inputs
    elif any(s in scan_match for s in Scanners.FORTIFY.keywords) and os.path.isfile(fpath):
        # Check file extension
        ext = os.path.splitext(fpath)[1]
        if ext not in Scanners.FORTIFY.valid_ext:
            return f"File extension \'{ext}\' not supported for {scanner} input"
        
        # Alert for fortify fpr files
        if not FORTIFY_FILE_WARNED_ONCE and os.path.isfile(fpath) and fpath.endswith('.fpr'):
            FORTIFY_FILE_WARNED_ONCE = True
            if parsers.GUI_MODE:
                _end = f" If {parsers.PROG_NAME_ABBR} takes too long to complete, stop execution at the loading screen and immediately rerun using the CLI executable."
            else:
                _end = ""
            console(f"A Fortify .fpr file has been detected. Fpr files are compressed archives that require unzipping. Processing times will be fairly long if the uncompressed data is large, so {parsers.PROG_NAME_ABBR} will appear to freeze or hang." + _end, title='FPR File Detected', type='warning', orig_name=__name__)
        
        # For fortify inputs, check if the audit.fvdl file is present in the fpr archive
        if any(s in scan_match for s in Scanners.FORTIFY.keywords) and not parsers.fortify.check_fvdl(fpath):
            return "The specified Fortify FPR archive does not contain an \'audit.fvdl\' file. The archive may be corrupted or the scanner output is invalid."

    # All other inputs
    elif os.path.isfile(fpath):
        
        selected_scanner = select_scanner(scanner)
        if selected_scanner is None:
            return f"Scanner \'{scanner}\' not supported."
        else:
            # Check valid extensions
            ext = os.path.splitext(fpath)[1] 
            if ext not in selected_scanner.valid_ext:
                return f"File extension \'{ext}\' not supported for {scanner} input"

    # If it is not a file, input is invalid
    else:
        return "Invalid {} input, path does not exist: {}".format(scanner, fpath)
    
    # All checks pass
    return "TRUE"

def validate_outfile(outfile):
    # Check if outfile is defined
    if outfile is not None and len(outfile) <= 0:
        return "Outfile not defined"
    
    # Check if outfile parent directory exists
    if ('\\' in outfile or '/' in outfile) and not os.path.isdir(os.path.dirname(outfile)):
        return "Parent directory of outfile does not exist"

    ext = os.path.splitext(outfile)[1]
    if ext not in Scanners.SARP.valid_ext:
        return f"Outfile must end with one of the following extensions: {Scanners.SARP.valid_ext}"
    
    return "TRUE"

def load_config_cwe_category_mappings():
    # Load MITRE Category Mappings for each CWE
    try:
        with open(os.path.join(parsers.MAPPINGS_DIR, 'mitre_cwe_category_mapping.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
    except (FileNotFoundError, json.JSONDecodeError):
        console(f"Unable to load MITRE CWE Category Mappings: Invalid JSON format\n{parsers.PROG_NAME_ABBR} will continue without CWE category mappings.", "Config Error", type='error', orig_name=__name__)
        return {}

def load_config_user_inputs(inputs_path, default_outfile="output.xlsx", default_control_flags=None):
    # Check if there are inputs in the inputs file
    if len(inputs_path) <= 0:
        if default_control_flags is not None: 
            return [], default_outfile, default_control_flags
        else:
            return [], default_outfile, {}
    if os.path.isfile(inputs_path):
        try:
            with open(inputs_path, 'r', encoding='utf-8-sig') as uin:
                user_inputs = json.load(uin)
        except (FileNotFoundError, json.JSONDecodeError):
            return f"Unable to parse \"{os.path.basename(inputs_path)}.\" This may be due to an improperly formatted or corrupted JSON file."
        
        # Attempt to parse project name and version
        parsers.PROJ_NAME = user_inputs.get('project_name', "")
        parsers.PROJ_VERSION = user_inputs.get('project_version', "")
        
        # Attempt to parse the main inputs
        if 'main' not in user_inputs.keys() and len(user_inputs['main']) <= 0:
            return f"Error in parsing config file \'{inputs_path}\'. No inputs defined in \"main\"."
        
        # Check if each input contains the right keys
        expected_keys = set(InputDictKeys.inputs())
        if not all(set(inp) == expected_keys for inp in user_inputs["main"]):
            return f"Error in parsing config file \'{inputs_path}\'. " + "Invalid keys detected in \"main\". All of the following keys (and only these keys) must be defined: {}.".format(", ".join(InputDictKeys.inputs()))

        # All is green, set main equal to parser_inputs
        parser_inputs = user_inputs['main']
        
        # Check for outfile
        if 'outfile' in user_inputs.keys():
            if user_inputs['outfile'] is not None or len(user_inputs['outfile']) > 0:
                parser_outfile = user_inputs['outfile'] 
            else: parser_outfile = default_outfile
        else: parser_outfile = default_outfile
        
        # Check to see if slashes are present, if not, then assume pwd
        if not ('\\' in parser_outfile or '/' in parser_outfile):
            parser_outfile = os.path.join(os.getcwd(), parser_outfile)
        
        # Check for control flags
        if 'flags' in user_inputs.keys():
            for k in user_inputs['flags'].keys():
                if k not in [f.flag for f in InputConfigFlags]:
                    return f"Error in parsing config file \'{inputs_path}\'. " + "Invalid key \'{}\' detected in \"flags\". Only the following keys are permitted: {}.".format(k, ", ".join([f.flag for f in InputConfigFlags]))
        else:
            control_flags = {}

        # All is green, set flags equal to control_flags
        control_flags = user_inputs['flags']
        
        # Fill in empty flags with default values
        for f in InputConfigFlags:
            if f.flag not in control_flags.keys():
                control_flags[f.flag] = f.default
        
        # Set inputs path global for export
        parsers.INPUTS_PATH = inputs_path
        
        # Completed parsing
        return parser_inputs, parser_outfile, control_flags

    else:
        return f"Config file {inputs_path} not found."

def check_input_format(inputs, outfile, flags):
    # Check if inputs are correct
    success = True
        
    for inp in inputs:
        # Check if path and scanner exist
        if (msg := validate_path_and_scanner(inp[InputDictKeys.PATH.value], inp[InputDictKeys.SCANNER.value])) != 'TRUE':
            console(msg, title='Invalid Config Input', type='error', orig_name=__name__)
            success = False
    
    # Check outfile
    msg = validate_outfile(outfile)
    if msg == "Outfile not defined":
        pass
    elif msg != 'TRUE':
        console(msg, title='Invalid Config Input', type='error', orig_name=__name__)
        success = False
    
    # Check control flags
    for k, v in flags.items():
        if k not in [f.flag for f in InputConfigFlags]:
            console(f"Invalid control flag \"{k}\". Only the following control flags are allowed: {[f.flag for f in InputConfigFlags]}", title='Invalid Config Input', type='error', orig_name=__name__)
            success = False
        if not isinstance(v, bool):
            console(f"Invalid data type for control flag \"{k}\". Please ensure all values are boolean types.", title='Invalid Config Input', type='error', orig_name=__name__)
            success = False
    
    # Check if all control flags are present
    missing = [f"\'{f}\'" for f in [t_f.flag for t_f in InputConfigFlags] if f not in flags.keys()]
    if len(missing) > 0 and not parsers.GUI_MODE:
        console(f"Missing control flag{'s' if len(missing, orig_name=__name__) > 1 else ''} {', '.join(missing)}", title='Invalid Config Input', type='error')
        success = False

    return success

def dedupe_parser_inputs(p_inputs):
    if len(p_inputs) <= 0:
        return p_inputs
    
    # Dedupe main scanner inputs
    seen = set()
    inputs = [
        d for d in p_inputs
        if (key := tuple(d[k] for k in d.keys())) not in seen and not seen.add(key)
    ]
    return inputs

def check_all_CWEs(data):
    count = 0
    
    # Check if cwe is in categories dict
    for i, row in enumerate(data, start=1):
        # Control flag check
        if parsers.control_flags[InputConfigFlags.OVERRIDE_VULN_MAPPING.flag]:
            progress_bar(i, len(data), prefix=InputConfigFlags.OVERRIDE_VULN_MAPPING.flag.rjust(SPACE))
            row[Fieldnames.SCORING_BASIS.value], count = check_CWE_category(row[Fieldnames.SCORING_BASIS.value], count)
        
        # Turn CWE into int if capable
        row[Fieldnames.SCORING_BASIS.value] = int(row[Fieldnames.SCORING_BASIS.value]) if str(row[Fieldnames.SCORING_BASIS.value]).isdigit() else row[Fieldnames.SCORING_BASIS.value]
    logger.info("Identified %d CWE IDs that may require remapping", count)

def check_CWE_category(cwe, count=0):
    if cwe in parsers.cwe_categories.keys():
        return f"{cwe}:{parsers.cwe_categories[cwe]}", count + 1
    else:
        return cwe, count

def export_config(inputs, outfile, control_flags, no_overwrite=False):
    out_dict = {InputSchemaKeys.SCHEMA.value: "../schemas/user_inputs.schema.json",
                InputSchemaKeys.PROJ_NAME.value: parsers.PROJ_NAME,
                InputSchemaKeys.PROJ_VERSION.value: parsers.PROJ_VERSION,
                InputSchemaKeys.MAIN.value: inputs,
                InputSchemaKeys.OUTFILE.value: outfile,
                InputSchemaKeys.FLAGS.value: control_flags}
    
    # Set up output path
    if no_overwrite or len(parsers.INPUTS_PATH) <= 0:
        if len(parsers.PROJ_NAME) <= 0:
            basename = parsers.PROG_NAME_ABBR.lower()+'_inputs'
        else:
            basename = "_".join(part for part in [parsers.PROJ_NAME.replace(' ', '_'), parsers.PROJ_VERSION.replace(' ', '_')] if len(part.strip()) > 0)
        # Add -# to basename if file exists
        if no_overwrite and os.path.isfile(os.path.join(parsers.INPUTS_DIR, basename+'.json')):
            i = 1
            while True:
                if os.path.isfile(os.path.join(parsers.INPUTS_DIR, basename+f'-{i}.json')):
                    i += 1
                else: break
            basename += f'-{i}'
                
        parsers.INPUTS_PATH = os.path.join(parsers.INPUTS_DIR, basename+'.json')
    
    with open(parsers.INPUTS_PATH, 'w', encoding='utf-8-sig') as uout:
        json.dump(out_dict, uout, indent=4)


def generate_preview(preview, remove_substr='', add_substr=''):
    if remove_substr and remove_substr in preview:
        preview = preview.replace(remove_substr, '', 1)
    
    if add_substr:
        preview = add_substr + preview
    
    return preview

def message_box(title, msg, type):
    if type == 'error':
        messagebox.showerror(title, msg)
    elif type == 'warning':
        messagebox.showwarning(title, msg)
    elif type == 'info':
        messagebox.showinfo(title, msg)

def console(msg, title='', type='info', orig_name=__name__):
    if parsers.GUI_MODE:
        message_box(title, msg, type)
    else:
        print(f'\n[{type.upper()}]  {msg}')
        
    t_logger = logging.getLogger(orig_name)
    
    if type == 'critical':
        t_logger.critical(msg)
    elif type == 'error':
        t_logger.error(msg)
    elif type == 'warning':
        t_logger.warning(msg)
    elif type == 'info':
        t_logger.info(msg)

def get_file_size_mb(path):
    size_bytes = os.path.getsize(path)
    size_mb = size_bytes // (1024 * 1024)
    return size_mb

def format_time(seconds):
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    seconds = int(seconds % 60)

    return f"{hours:02}:{minutes:02}:{seconds:02}"

def get_all_previews(inputs):
    previews = {}
    
    for inp in inputs:
        fpath = inp[InputDictKeys.PATH.value]
        scanner = inp[InputDictKeys.SCANNER.value]
        preview = ''
    
        fp = os.path.realpath(fpath)
        
        selected_scanner = select_scanner(scanner)
        if selected_scanner is None:
            preview = f"[ERROR] Unsupported scanner {scanner}, unable to show preview"
        else:
            module = importlib.import_module(selected_scanner.module)
            preview = module.path_preview(fp)

        previews[fpath] = preview
    
    return previews

def select_scanner(scanner):
    # Returns enum corresponding to scanner text, else returns None
    scan_match = scanner.lower().replace(' ', '')
    
    for scanner_enum in Scanners:
        if scanner_enum == Scanners.SARIF: continue
        if any(s in scan_match for s in scanner_enum.keywords):
            return scanner_enum
    
    # Explicitly do SARIF last
    if any(s in scan_match for s in Scanners.SARIF.keywords):
        return scanner_enum
    
    return None
    

def print_user_inputs_template():
    flags = ""
    for f in [f.flag for f in InputConfigFlags]:
        flags += f'        "{f}": [true|false],\n'
    flags = flags.rstrip(',\n')
    
    s = f"""{{
    "$schema": "../schemas/user_inputs.schema.json",
    "project_name": "example_proj",
    "project_version": "v1.0",
    "main": [
        {{
            "scanner": "CPPCheck",
            "path": "C:\\\\Users\\\\...\\\\Documents\\\\project1\\\\scan_results\\\\cppcheck-output.xml",
            "remove": "C:\\\\Users\\\\...\\\\Documents\\\\project1\\\\top_level_src_dir",
            "prepend": ""
        }},
        {{
            "scanner": "Coverity v2023.2.5",
            "path": "/home/user/project2/coverity_results/coverity-output.json",
            "remove": "/home/user/project2/top_level_src_dir/second_level",
            "prepend": "replacement_second_level"
        }},
        {{
            "scanner": "GNAT SAS 24.0",
            "path": "../../../../scan_results_relative_to_pwd/gnatsas-output.json",
            "remove": "",
            "prepend": "top_level_src_dir/"
        }}
    ],
    "outfile": "path/to/outfile.[xlsx|csv]",
    "flags": {{
{flags}
    }}
}}"""
    print(s, sep='', end='')
