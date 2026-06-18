# toolbox.py

import os
import logging
import json
from enum import Enum
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
    
    INPUTS = [PATH, SCANNER, PREPEND, REMOVE]

class InputConfigFlags(Enum):
    OVERRIDE_VULN_MAPPING = (parsers.FLAG_CATEGORY_MAPPING, True)
    PREFLIGHT_RULES = (parsers.FLAG_PREFLIGHT_RULES, True)
    DEFAULT_PREFLIGHT_RULES = (parsers.FLAG_DEFAULT_PREFLIGHT_RULES, True)
    DUPE_SCAN_CONSOLIDATION = (parsers.FLAG_DUPE_SCAN_CONSOLIDATION, False)

    def __init__(self, flag, default):
        self.flag = flag
        self.default = default

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

def validate_path_and_scanner(fpath, scanner):
    global __excel_enabled, FILE_SIZE_WARNED_ONCE, FORTIFY_FILE_WARNED_ONCE
    scan_match = scanner.lower().replace(' ', '')
    
    if not any(s in scan_match for s in parsers.scanner_keywords):
        return "{} does not currently support input from {}. A list of acceptable scanners and their file types is in the readme.txt file.".format(parsers.PROG_NAME, scanner)
    
    # Alert for large file size for CLI
    if not FILE_SIZE_WARNED_ONCE and os.path.isfile(fpath) and get_file_size_mb(fpath) > LARGE_FILE_THRESHOLD_MB:
        FILE_SIZE_WARNED_ONCE = True
        if parsers.GUI_MODE:
            _end = " If SARP takes too long to complete, stop execution at the loading screen and immediately rerun using the CLI executable."
        else:
            _end = ""
        console("A large input file has been detected. Processing times may be fairly long, so SARP will appear to freeze or hang." + _end, title='Large File Detected', type='warning')
    
    # Alert for fortify fpr files
    if not FORTIFY_FILE_WARNED_ONCE and os.path.isfile(fpath) and fpath.endswith('.fpr'):
        FORTIFY_FILE_WARNED_ONCE = True
        if parsers.GUI_MODE:
            _end = " If SARP takes too long to complete, stop execution at the loading screen and immediately rerun using the CLI executable."
        else:
            _end = ""
        console("A Fortify .fpr file has been detected. Fpr files are compressed archives that require unzipping. Processing times will be fairly long if the uncompressed data is large, so SARP will appear to freeze or hang." + _end, title='FPR File Detected', type='warning')

    # Checkmarx inputs
    if any(s in scan_match for s in parsers.xmarx_keywords) and os.path.exists(fpath):
        if os.path.isdir(fpath):
            # Check if directory contains at least one csv file
            if len(os.listdir(fpath)) <= 0 or (len([file for file in os.listdir(fpath) if (file.endswith('.csv') or file.endswith('.xml'))]) <= 0):
                return "No CSV or XML files in the specified directory \'{}\'".format(fpath)
        else:
            return "Checkmarx input must be a directory, not a file"
    
    # AIO parser inputs
    elif any(s in scan_match for s in parsers.aio_keywords) and os.path.isfile(fpath):
        # Check file extension
        ext = os.path.splitext(fpath)[1]
        if ext not in ['.csv', '.xlsx']:
            return f"File extension \'{ext}\' not supported for {scanner} input"
        
        # Diverge depending on .xlsx or .csv
        if __excel_enabled and ext == '.xlsx':
            # Excel - Extract headers
            workbook = openpyxl.load_workbook(fpath)
            sheet = workbook[workbook.sheetnames[0]]
            headers = [cell.value for cell in sheet[1]]
        else:
            # CSV - Extract headers
            with open(fpath, 'r', encoding='utf-8-sig') as f:
                headers = f.readline().strip().split(',')
        
        if not all(h in Fieldnames.HEADERS.value for h in headers):
            # Doesn't match any expected headers
            return f"Input for scanner {scanner} does not match expected fieldnames.\n    {headers}\n  Ensure all of the headers match the following format:\n    {Fieldnames.HEADERS.value}\n"

    # All other inputs
    elif os.path.isfile(fpath):
        ext = os.path.splitext(fpath)[1]
        if ext not in parsers.valid_extensions:
            return f"File extension \'{ext}\' not supported for {scanner} input\n"
        
        # For fortify inputs, check if the audit.fvdl file is present in the fpr archive
        if any(s in scan_match for s in parsers.fortify_keywords) and not parsers.fortify.check_fvdl(fpath):
            return "The specified Fortify FPR archive does not contain an \'audit.fvdl\' file. The archive may be corrupted or the scanner output is invalid."

    # If it is not a file, input is invalid
    else:
        return "Invalid {} input, path does not exist: {}\n".format(scanner, fpath)
    
    # All checks pass
    return "TRUE"

def validate_outfile(outfile):
    # Check if outfile is defined
    if outfile is not None and len(outfile) <= 0:
        return "Outfile not defined"
    
    # Check if outfile parent directory exists
    if ('\\' in outfile or '/' in outfile) and not os.path.isdir(os.path.dirname(outfile)):
        return "Parent directory of outfile does not exist"

    if not (outfile.endswith('.xlsx') ^ outfile.endswith('.csv')):
        return "Outfile must end with either '.xslx' or '.csv'"
    
    return "TRUE"

def load_config_cwe_category_mappings():
    # Load MITRE Category Mappings for each CWE
    try:
        with open(os.path.join(parsers.MAPPINGS_DIR, 'mitre_cwe_category_mapping.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
    except (FileNotFoundError, json.JSONDecodeError):
        console("Unable to load MITRE CWE Category Mappings: Invalid JSON format\nSARP will continue without CWE category mappings.", "Config Error", type='error')
        return {}

def load_config_user_inputs(inputs_path, default_outfile="sarp_output.xlsx", default_control_flags=None):
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
        if not all([all([sorted(list(inp.keys())) == sorted(InputDictKeys.INPUTS.value)]) for inp in user_inputs['main']]):
            return f"Error in parsing config file \'{inputs_path}\'. " + "Invalid keys detected in \"main\". All of the following keys (and only these keys) must be defined: {}.".format(", ".join(InputDictKeys.INPUTS.value))

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
            console(msg, title='Invalid Config Input', type='error')
            success = False
    
    # Check outfile
    msg = validate_outfile(outfile)
    if msg == "Outfile not defined":
        pass
    elif msg != 'TRUE':
        console(msg, title='Invalid Config Input', type='error')
        success = False
    
    # Check control flags
    for k, v in flags.items():
        if k not in [f.flag for f in InputConfigFlags]:
            console(f"Invalid control flag \"{k}\". Only the following control flags are allowed: {[f.flag for f in InputConfigFlags]}", title='Invalid Config Input', type='error')
            success = False
        if not isinstance(v, bool):
            console(f"Invalid data type for control flag \"{k}\". Please ensure all values are boolean types.", title='Invalid Config Input', type='error')
            success = False
    
    # Check if all control flags are present
    missing = [f"\'{f}\'" for f in [t_f.flag for t_f in InputConfigFlags] if f not in flags.keys()]
    if len(missing) > 0 and not parsers.GUI_MODE:
        console(f"Missing control flag{'s' if len(missing) > 1 else ''} {', '.join(missing)}", title='Invalid Config Input', type='error')
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
        if parsers.control_flags[parsers.FLAG_CATEGORY_MAPPING]:
            progress_bar(i, len(data), prefix=InputConfigFlags.OVERRIDE_VULN_MAPPING.flag.rjust(SPACE))
            row[Fieldnames.SCORING_BASIS.value], count = check_CWE_category(row[Fieldnames.SCORING_BASIS.value], count)
        
        # Turn CWE into int if capable
        row[Fieldnames.SCORING_BASIS.value] = int(row[Fieldnames.SCORING_BASIS.value]) if str(row[Fieldnames.SCORING_BASIS.value]).isdigit() else row[Fieldnames.SCORING_BASIS.value]
    logger.info(f"Identified {count} CWE IDs that may require remapping")

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
            basename = parsers.PROG_NAME.lower().replace(" ", "_")
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

def console(msg, title='', type='info'):
    if parsers.GUI_MODE:
        from .inputs_gui import message_box
        message_box(title, msg, type)
    else:
        print(f'\n[{type.upper()}]  {msg}')
    
    if type == 'critical':
        logger.critical(msg)
    elif type == 'error':
        logger.error(msg)
    elif type == 'warning':
        logger.warning(msg)
    elif type == 'info':
        logger.info(msg)

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
    
        scan_match = scanner.lower().replace(' ', '')
        fp = os.path.realpath(fpath)
        
        if any(s in scan_match for s in parsers.aio_keywords):
            preview = parsers.aio.path_preview(fp)
        elif any(s in scan_match for s in parsers.xmarx_keywords):
            preview = parsers.checkmarx.path_preview(fp)
        elif any(s in scan_match for s in parsers.coverity_keywords):
            preview = parsers.coverity.path_preview(fp)
        elif any(s in scan_match for s in parsers.cppcheck_keywords):
            preview = parsers.cppcheck.path_preview(fp)
        elif any(s in scan_match for s in parsers.manualcve_keywords):
            preview = 'No preview available for NVD CVEs'
        elif any(s in scan_match for s in parsers.depcheck_keywords):
            preview = parsers.owasp_depcheck.path_preview(fp)
        elif any(s in scan_match for s in parsers.eslint_keywords):
            preview = parsers.eslint.path_preview(fp)
        elif any(s in scan_match for s in parsers.fortify_keywords):
            preview = parsers.fortify.path_preview(fp)
        elif any(s in scan_match for s in parsers.gnatsas_keywords):
            preview = parsers.gnatsas.path_preview(fp)
        elif any(s in scan_match for s in parsers.pragmatic_keywords):
            preview = parsers.pragmatic.path_preview(fp)
        elif any(s in scan_match for s in parsers.pylint_keywords):
            preview = parsers.pylint.path_preview(fp)
        elif any(s in scan_match for s in parsers.semgrep_keywords):
            preview = parsers.semgrep.path_preview(fp)
        elif any(s in scan_match for s in parsers.sigasi_keywords):
            preview = parsers.sigasi.path_preview(fp)
        elif any(s in scan_match for s in parsers.srm_keywords):
            preview = parsers.srm.path_preview(fp)
        else:
            preview = f"[ERROR] Unsupported scanner {scanner}, unable to show preview"

        previews[fpath] = preview
    
    return previews

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
