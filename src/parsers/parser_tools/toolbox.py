# toolbox.py

import os
import sys
import logging
import json
from enum import Enum
from . import *
import parsers
from parsers import *

__excel_enabled = False
try:
    import openpyxl
    __excel_enabled = True
except ImportError:
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
    OVERRIDE_VULN_MAPPING = FLAG_VULN_MAPPING
    OVERRIDE_CWE = FLAG_OVERRIDE_CWE
    OVERRIDE_CONFIDENCE = FLAG_OVERRIDE_CONFIDENCE
    FORCE_EXPORT_CSV = FLAG_FORCE_EXPORT_CSV
    
    INPUTS = [PATH, SCANNER, PREPEND, REMOVE]
    FLAGS = [OVERRIDE_VULN_MAPPING, OVERRIDE_CWE, OVERRIDE_CONFIDENCE, FORCE_EXPORT_CSV]
    
    def __str__(self):
        return self.value

def validate_path_and_scanner(fpath, scanner):
    global __excel_enabled, FILE_SIZE_WARNED_ONCE, FORTIFY_FILE_WARNED_ONCE
    scan_match = scanner.lower().replace(' ', '')
    
    if not any(s in scan_match for s in parsers.scanner_keywords):
        return "The script does not support input from {}. A list of acceptable scanners and their file types is in the readme.txt file.".format(scanner)
    
    # Alert for large file size for CLI
    if not FILE_SIZE_WARNED_ONCE and os.path.isfile(fpath) and get_file_size_mb(fpath) > LARGE_FILE_THRESHOLD_MB:
        FILE_SIZE_WARNED_ONCE = True
        console("A large input file has been detected. Processing times may be fairly long, so the program will appear to freeze or hang.", title='Large File Detected', type='warning')
    
    # Alert for fortify fpr files
    if not FORTIFY_FILE_WARNED_ONCE and os.path.isfile(fpath) and fpath.endswith('.fpr'):
        FORTIFY_FILE_WARNED_ONCE = True
        console("A Fortify .fpr file has been detected. Fpr files are compressed archives that require unzipping. Processing times will be fairly long if the uncompressed data is large, so the program will appear to freeze or hang.", title='FPR File Detected', type='warning')

    # Checkmarx inputs
    if any(s in scan_match for s in parsers.xmarx_keywords) and os.path.exists(fpath):
        if os.path.isdir(fpath):
            # Check if directory contains at least one csv file
            if len(os.listdir(fpath)) <= 0 or (len([file for file in os.listdir(fpath) if file.endswith('.csv')]) <= 0):
                return "No CSV files in the specified directory \'{}\'".format(fpath)
            else:
                # Change fieldnames to xmarx fieldnames
                parsers.fieldnames = parsers.xmarx_fieldnames
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
        
        if all(h in parsers.fieldnames for h in headers):
            # fieldnames don't change
            pass
        elif all(h in parsers.xmarx_fieldnames for h in headers):
            # Change fieldnames to xmarx fieldnames
            parsers.fieldnames = parsers.xmarx_fieldnames
        else:
            # Doesn't match any expected headers
            return f"Input for scanner {scanner} does not match expected fieldnames.\n    {headers}\n  Ensure all of the headers match one of the following configurations:\n    {parsers.fieldnames}\n    {parsers.xmarx_fieldnames}\n"

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

    return "TRUE"

def load_config():
    # Check if there are inputs in user_inputs.json
    inputs_path = os.path.join(parsers.CONFIG_DIR, 'user_inputs.json')
    if os.path.isfile(inputs_path):
        try:
            with open(inputs_path, 'r', encoding='utf-8-sig') as uin:
                user_inputs = json.load(uin)
        except json.JSONDecodeError:
            return f"Unable to parse \"{os.path.basename(inputs_path)}.\" This may be due to an improperly formatted or corrupted JSON file."
        
        # Attempt to parse the main inputs
        if 'main' not in user_inputs.keys() and len(user_inputs['main']) <= 0:
            return "Error in parsing config file \'user_inputs.json\'. No inputs defined in \"main\"."
        
        # Check if each input contains the right keys
        if not all([all([sorted(list(inp.keys())) == sorted(InputDictKeys.INPUTS.value)]) for inp in user_inputs['main']]):
            return "Error in parsing config file \'user_inputs.json\'. Invalid keys detected in \"main\". Only the following keys are permitted: {}, {}, {}, {}.".format(*InputDictKeys.INPUTS.value)

        # All is green, set main equal to parser_inputs
        parser_inputs = user_inputs['main']
        
        # Check for outfile
        if 'outfile' in user_inputs.keys():
            if user_inputs['outfile'] is not None or len(user_inputs['outfile']) > 0:
                parser_outfile = user_inputs['outfile'] 
            else: parser_outfile = ""
        else: parser_outfile = ""
        
        # Check for control flags
        if 'flags' in user_inputs.keys():
            for k in user_inputs['flags'].keys():
                if k not in InputDictKeys.FLAGS.value:
                    return "Error in parsing config file \'user_inputs.json\'. Invalid key \'{}\' detected in \"flags\". Only the following keys are permitted: {}, {}, {}, {}.".format(k, *InputDictKeys.FLAGS.value)
        else:
            control_flags = {}

        # All is green, set flags equal to control_flags
        control_flags = user_inputs['flags']
        
        # Completed parsing
        return parser_inputs, parser_outfile, control_flags

    else:
        return "Config file \'user_inputs.json\' not found."

def check_input_format(inputs, outfile, flags):
    # Check if inputs are correct
    failure = False
        
    for inp in inputs:
        # Check if path and scanner exist
        if (msg := validate_path_and_scanner(inp[InputDictKeys.PATH.value], inp[InputDictKeys.SCANNER.value])) != 'TRUE':
            console(msg, title='Invalid Config Input', type='error')
            failure = True
            logger.critical("There were errors detected for input \"{}\". Please address them in the log file then run the program again.".format(inp[InputDictKeys.PATH.value]))
    
    # Check outfile
    msg = validate_outfile(outfile)
    if msg == "Outfile not defined":
        pass
    elif msg != 'TRUE':
        console(msg, title='Invalid Config Input', type='error')
        failure = True
        logger.critical("There were errors when validating the outfile. Please address them in the log file then run the program again.")
    
    # Check control flags
    for k, v in flags.items():
        if not isinstance(v, bool):
            console(f"Invalid data type for control flag \"{k}\". Please ensure all values are boolean types.", title='Invalid Config Input', type='error')
            failure = True
            logger.critical("There were errors when validating the control flags. Please address them in the log file then run the program again.")

    if failure:
        sys.exit(2)

def export_config(inputs, outfile, control_flags):
    inputs_path = os.path.join(parsers.CONFIG_DIR, 'user_inputs.json')
    with open(inputs_path, 'w', encoding='utf-8-sig') as uout:
        json.dump({'main': inputs, 'outfile': outfile, 'flags': control_flags}, uout, indent=4)


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
    
    if type == 'error':
        logger.error(msg)
    elif type == 'warning':
        logger.warning(msg)
    elif type == 'info':
        logger.info(msg)

def get_file_size_mb(path):
    size_bytes = os.path.getsize(path)
    size_mb = size_bytes // (1024 * 1024)
    return size_mb

def get_all_previews(inputs):
    previews = {}
    
    for inp in inputs:
        fpath = inp[InputDictKeys.PATH.value]
        scanner = inp[InputDictKeys.SCANNER.value]
    
        scan_match = scanner.lower().replace(' ', '')
        fp = os.path.realpath(fpath)
        
        if any(s in scan_match for s in parsers.aio_keywords):
            preview = aio.path_preview(fp)
        elif any(s in scan_match for s in parsers.xmarx_keywords):
            preview = checkmarx.path_preview(fp)
        elif any(s in scan_match for s in parsers.coverity_keywords):
            preview = coverity.path_preview(fp)
        elif any(s in scan_match for s in parsers.cppcheck_keywords):
            preview = cppcheck.path_preview(fp)
        elif any(s in scan_match for s in parsers.depcheck_keywords):
            preview = owasp_depcheck.path_preview(fp)
        elif any(s in scan_match for s in parsers.eslint_keywords):
            preview = eslint.path_preview(fp)
        elif any(s in scan_match for s in parsers.fortify_keywords):
            if os.path.splitext(fp)[1] == ".csv":
                preview = fortify_csv.path_preview(fp)
            elif os.path.splitext(fp)[1] == ".fpr":
                preview = fortify.path_preview(fp)
        elif any(s in scan_match for s in parsers.gnatsas_keywords):
            preview = gnatsas.path_preview(fp)
        elif any(s in scan_match for s in parsers.pragmatic_keywords):
            preview = pragmatic.path_preview(fp)
        elif any(s in scan_match for s in parsers.pylint_keywords):
            preview = pylint.path_preview(fp)
        elif any(s in scan_match for s in parsers.srm_keywords):
            if os.path.splitext(fp)[1] == ".csv":
                preview = srm_csv.path_preview(fp)
            elif os.path.splitext(fp)[1] == ".xml":
                preview = srm.path_preview(fp)
        else:
            preview = f"[ERROR] Unsupported scanner {scanner}, unable to show preview"

        previews[fpath] = preview
    
    return previews
