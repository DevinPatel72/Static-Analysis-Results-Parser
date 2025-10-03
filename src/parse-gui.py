#!/usr/bin/env python3

# Imports
import os
import sys
import traceback
from parsers.parser_tools.inputs_gui import YesNoGUI, InputsGUI, AdjustPathsGUI, OutfileFlagsGUI
from parsers.parser_tools.toolbox import InputDictKeys, console, load_config_user_inputs, load_config_cwe_category_mappings, export_config, check_input_format
import parsers
from parsers import PROG_NAME, VERSION
from parsers import *
from parsers.parser_tools import parser_writer
import parsers.parser_tools.progressbar as progressbar

parsers.GUI_MODE = True
progressbar.DISABLE_PROGRESS_BAR = True

# Configure root path and important dirs of script
if getattr(sys, 'frozen', False):
    # Running as bundled executable
    parsers.EXE_ROOT_DIR = os.path.dirname(sys.executable)
    logname = os.path.splitext(os.path.basename(sys.executable))[0]+'.log'
else:
    # Running as script
    parsers.EXE_ROOT_DIR = os.path.dirname(__file__)
    logname = os.path.splitext(os.path.basename(__file__))[0]+'.log'

parsers.CONFIG_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.CONFIG_DIR)

parsers.LOGS_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.LOGS_DIR)
os.makedirs(parsers.LOGS_DIR, exist_ok=True)
logfile = os.path.join(parsers.LOGS_DIR, logname)

# Configure logger
import logging
logging.basicConfig(filename=logfile, level=logging.INFO, format='%(name)-18s :: %(levelname)-8s :: %(message)s', filemode='w')
consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.CRITICAL)
consoleHandler.setFormatter(logging.Formatter(fmt='\n[%(levelname)s]  %(message)s'))
logging.getLogger().addHandler(consoleHandler)
logger = logging.getLogger(__name__)

from datetime import datetime
logger.info(f"{PROG_NAME} {VERSION}")
logger.info(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# Check if openpyxl is installed. Logged here to ensure correct placement in log file
from importlib.util import find_spec
if find_spec('openpyxl') is None:
    logger.warning('Module \'openpyxl\' not found, defaulting output to CSV.')
    # Handled in parser_writer.py

################################
# Main
################################

def main():
    
    parser_inputs = []
    parser_outfile = ""
    control_flags = {}
    
    # Ask user if they wish to load configuration data from file
    if os.path.isfile(os.path.join(parsers.CONFIG_DIR, 'user_inputs.json')):
        
        yesnogui = YesNoGUI("A user inputs file has been detected.\nWould you like to load this data?")
        uinput = yesnogui.result
        
        if uinput is None:
            sys.exit(0)
        
        # Load inputs from config file
        if uinput:
            rv = load_config_user_inputs()
            if isinstance(rv, str):
                if "Config file \'user_inputs.json\' not found." != rv:
                    logger.warning(f"{rv}")
                    console(f"{rv}\n\nDefaulting to using blank fields.", "Cannot load config", "warning")
                parser_inputs = []
                parser_outfile = ""
                control_flags = {}
            else:
                parser_inputs, parser_outfile, control_flags = rv
        # Else empty input
        else:
            parser_inputs = []
            parser_outfile = ""
            control_flags = {}
        
    # Check inputs format
    if len(parser_inputs) > 0:
        check_input_format(parser_inputs, parser_outfile, control_flags)
    
    inputs_gui = InputsGUI(parser_inputs)
    if not inputs_gui.cleanexit or (inputs_gui.results is None or len(inputs_gui.results) <= 0):
        sys.exit(0)
    
    adjust_paths_gui = AdjustPathsGUI(inputs_gui.results)
    if not adjust_paths_gui.cleanexit or (adjust_paths_gui.results is None or len(adjust_paths_gui.results) <= 0):
        sys.exit(0)
    
    parser_inputs = adjust_paths_gui.results
    
    outfile_flags_gui = OutfileFlagsGUI(parser_outfile, control_flags)
    if not outfile_flags_gui.cleanexit or (outfile_flags_gui.results is None or len(outfile_flags_gui.results) <= 0):
        sys.exit(0)
    
    parser_outfile = outfile_flags_gui.results[InputDictKeys.OUTFILE.value]
    control_flags = {
        FLAG_CATEGORY_MAPPING: outfile_flags_gui.results[InputDictKeys.OVERRIDE_VULN_MAPPING.value],
        FLAG_OVERRIDE_CWE: outfile_flags_gui.results[InputDictKeys.OVERRIDE_CWE.value],
        FLAG_OVERRIDE_CONFIDENCE: outfile_flags_gui.results[InputDictKeys.OVERRIDE_CONFIDENCE.value]
    }
    
    # Log the configuration
    s = "Reading from files:\n"
    for i, entry in enumerate(parser_inputs, start=1):
        fpath = entry[InputDictKeys.PATH.value]
        scanner = entry[InputDictKeys.SCANNER.value]
        substr = entry[InputDictKeys.REMOVE.value]
        prepend = entry[InputDictKeys.PREPEND.value]
        s += f"{i})  Scanner: {scanner}\n    Path: {fpath}\n    Path substring to delete: {substr}\n    Path substring to prepend: {prepend}\n"
    s += f"\nWriting to file: {parser_outfile}\n"
    s += "\nParser Switches:\n"
    s += "\n".join([f"  Enable {k}:".ljust(34) + f"{v}" for k,v in control_flags.items()]).strip('\n')
    
    logger.info("\n".join(['    ' + l for l in s.split('\n')]))
    
    # Export parser inputs to config file for reruns
    export_config(parser_inputs, parser_outfile, control_flags)
    
    # Load the mapping if true
    if control_flags[FLAG_CATEGORY_MAPPING]:
        parsers.cwe_categories = load_config_cwe_category_mappings()
        
    # Init the outfile
    if parser_outfile.lower().endswith('.csv'):
        force_csv = True
    else:
        force_csv = False
    parser_writer.open_writer(parser_outfile, parsers.fieldnames, force_csv=force_csv)

    # Track number of errors
    err_count = 0

    # Parse the inputs
    for entry in parser_inputs:
        fpath = entry[InputDictKeys.PATH.value]
        scanner = entry[InputDictKeys.SCANNER.value]
        substr = entry[InputDictKeys.REMOVE.value]
        prepend = entry[InputDictKeys.PREPEND.value]
        
        
        scan_match = scanner.lower().replace(' ', '')
        path = os.path.realpath(fpath)
        
        if any(s in scan_match for s in parsers.aio_keywords):
            err_count += aio.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.xmarx_keywords):
            err_count += checkmarx.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.coverity_keywords):
            err_count += coverity.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.cppcheck_keywords):
            err_count += cppcheck.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.depcheck_keywords):
            err_count += owasp_depcheck.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.eslint_keywords):
            err_count += eslint.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.manualcve_keywords):
            err_count += manual_cve.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.gnatsas_keywords):
            err_count += gnatsas.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.fortify_keywords):
            err_count += fortify.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.pragmatic_keywords):
            err_count += pragmatic.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.pylint_keywords):
            err_count += pylint.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.semgrep_keywords):
            err_count += semgrep.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.sigasi_keywords):
            err_count += sigasi.parse(path, scanner, substr, prepend, control_flags)
        elif any(s in scan_match for s in parsers.srm_keywords):
            err_count += srm.parse(path, scanner, substr, prepend, control_flags)
        else:
            logger.error(f"Unsupported scanner. Skipped {fpath},{scanner}")
            err_count += 1
        
    
    parser_writer.close_writer()
    
    if err_count > 0:
        console(f"{err_count} errors have been detected while parsing files.\nPlease see logfile \"{logfile}\" for more details.", 'Errors Detected', 'warning')
        
    
    logger.info("Parsing complete!")
    console("Parsing Complete!", PROG_NAME, 'info')
    
    

if __name__ == "__main__":
    exitcode = 0
    try:
        main()
    except SystemExit as se:
        exitcode = se.code
    except KeyboardInterrupt:
        logger.info("Script terminated by user...")
        sys.exit(0)
    except PermissionError:
        logger.critical("File access error. Please do not open or lock an input file while the parser is running.")
        exitcode = 2
    except:
        console(f"Uncaught exception caused the script to crash.\nException trace has been output to \"{logfile}\"", "Critical Error", "error")
        logger.error("\n" + traceback.format_exc())
        exitcode = 1
    finally:
        logger.info(f"Script terminated with exit code {exitcode}")
        sys.exit(exitcode)