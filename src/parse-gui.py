#!/usr/bin/env python3

# Imports
import os
import sys
import traceback
from parsers.parser_tools.inputs_gui import InputsGUI, AdjustPathsGUI, OutfileFlagsGUI
from parsers.parser_tools.load_user_inputs_gui import JsonInputPreviewGUI
from parsers.parser_tools.preflight_gui import RuleBuilderGUI
from parsers.parser_tools.toolbox import InputDictKeys, InputConfigFlags, Fieldnames, console, load_config_user_inputs, load_config_cwe_category_mappings, export_config, check_input_format, dedupe_parser_inputs
import parsers
from parsers import PROG_NAME, VERSION
from parsers import *
from parsers.parser_tools import parser_writer, preflight
import parsers.parser_tools.progressbar as progressbar
from parsers.parser_tools.begin_parse import begin

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

# Capitalized drive letter if on Windows
drive, rest = os.path.splitdrive(parsers.EXE_ROOT_DIR)
if len(drive) > 0: drive = drive.upper()
parsers.EXE_ROOT_DIR = os.path.join(drive, rest)

# Set import directories
parsers.CONFIG_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.CONFIG_DIR)
parsers.MAPPINGS_DIR = os.path.join(parsers.CONFIG_DIR, parsers.MAPPINGS_DIR)
parsers.PREFLIGHT_DIR = os.path.join(parsers.CONFIG_DIR, parsers.PREFLIGHT_DIR)

# Create inputs directory
parsers.INPUTS_DIR = os.path.join(parsers.CONFIG_DIR, parsers.INPUTS_DIR)
os.makedirs(parsers.INPUTS_DIR, exist_ok=True)

# Set log paths
parsers.LOGS_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.LOGS_DIR)
os.makedirs(parsers.LOGS_DIR, exist_ok=True)
logfile = os.path.join(parsers.LOGS_DIR, logname)
parsers.LOGFILE = logfile

# Configure logger
import logging
logging.basicConfig(filename=logfile, level=logging.INFO, encoding='utf-8', format='%(name)-18s :: %(levelname)-8s :: %(message)s', filemode='w')
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

# Check if matplotlib is installed. Logged here to ensure correct placement in log file
if find_spec('matplotlib') is None:
    logger.warning(f'Module \'matplotlib\' not found, {parsers.PROG_NAME_ABBR} will skip chart reporting.')
    # Handled in reporting.py

################################
# Main
################################

def main():
    parser_inputs = []
    parser_outfile = ""
    control_flags = {}
    
    # Load inputs if there are any
    select_input = None
    if len(os.listdir(parsers.INPUTS_DIR)) > 0:
        select_input = JsonInputPreviewGUI()
        
        # Load inputs from config file
        if select_input.cleanexit and select_input.results is not None:
            rv = load_config_user_inputs(select_input.results)
            if isinstance(rv, str):
                if f"Config file {select_input.results} not found." != rv:
                    logger.warning(f"{rv}")
                    console(f"{rv}\n\nDefaulting to using blank fields.", "Cannot load config", "warning")
                parser_inputs = []
                parser_outfile = ""
                control_flags = {}
            else:
                parser_inputs, parser_outfile, control_flags = rv
        # Else exit
        else:
            sys.exit(0)
    
    # Dedupe parser_inputs
    parser_inputs = dedupe_parser_inputs(parser_inputs)
    
    # Check inputs format
    if len(parser_inputs) > 0:
        check_input_format(parser_inputs, parser_outfile, control_flags)
    
    # Skip all the GUI steps if Execute button is selected
    if select_input is None or not select_input.execute_now:
        inputs_gui = InputsGUI(parser_inputs)
        if not inputs_gui.cleanexit or (inputs_gui.results is None or len(inputs_gui.results) <= 0):
            sys.exit(0)
            
        parsers.PROJ_NAME = inputs_gui.results_project_name
        parsers.PROJ_VERSION = inputs_gui.results_project_version
        
        adjust_paths_gui = AdjustPathsGUI(inputs_gui.results)
        if not adjust_paths_gui.cleanexit or (adjust_paths_gui.results is None or len(adjust_paths_gui.results) <= 0):
            sys.exit(0)
        
        parser_inputs = adjust_paths_gui.results
        
        outfile_flags_gui = OutfileFlagsGUI(parser_outfile, control_flags)
        if not outfile_flags_gui.cleanexit or (outfile_flags_gui.results is None or len(outfile_flags_gui.results) <= 0):
            sys.exit(0)
        
        parser_outfile = outfile_flags_gui.results[InputDictKeys.OUTFILE.value]
        control_flags = {f.flag: outfile_flags_gui.results[f.flag]
                        for f in InputConfigFlags
                        if f._module_visibility == 'OutfileFlagsGUI'}
        
        # If the checkbox was enabled, ask if user wants to edit the preflight rules
        if control_flags[FLAG_PREFLIGHT_RULES]:
            # Load the preflight rules
            preflight.load_prules()

            rulebuildergui = RuleBuilderGUI(parsers.prules)
            
            if rulebuildergui.result is not None:
                parsers.prules = rulebuildergui.result
            
            if rulebuildergui.enable_default_rules is not None:
                control_flags[FLAG_DEFAULT_PREFLIGHT_RULES] = rulebuildergui.enable_default_rules
            else:
                control_flags[FLAG_DEFAULT_PREFLIGHT_RULES] = True
            
            if rulebuildergui.result is None and rulebuildergui.enable_default_rules is None:
                sys.exit(0)
        else:
            parsers.prules = []
            control_flags[FLAG_DEFAULT_PREFLIGHT_RULES] = True
    
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
    s += "\n".join([f"  Enable {k}:".ljust(42) + f"{v}" for k,v in control_flags.items()]).strip('\n')
    
    logger.info("\n".join(['    ' + l for l in s.split('\n')]))
    
    # Export parser inputs to config file for reruns. If reading from a selected inputs file, overwrite it instead of creating a new file.
    if select_input is None:
        no_overwrite = False
    else: no_overwrite = not (select_input.results is not None and len(select_input.results) > 0)
    export_config(parser_inputs, parser_outfile, control_flags, no_overwrite=no_overwrite)
    
    # Put control_flags into module variable
    parsers.control_flags = control_flags
    
    # Save the preflight rules
    preflight.save_prules(parsers.prules)
    
    # Load the mapping if true
    if control_flags[InputConfigFlags.OVERRIDE_VULN_MAPPING.flag]:
        parsers.cwe_categories = load_config_cwe_category_mappings()

    # Init the outfile
    force_csv = parser_outfile.lower().endswith('.csv')
    force_sarif = parser_outfile.lower().endswith('.json') or parser_outfile.lower().endswith('.sarif')
    parser_writer.open_writer(parser_outfile, Fieldnames.HEADERS.value, force_csv=force_csv, force_sarif=force_sarif)
    
    begin(parser_inputs)
    
    

if __name__ == "__main__":
    exitcode = 0
    try:
        main()
    except SystemExit as se:
        exitcode = se.code
    except KeyboardInterrupt:
        logger.info("Program terminated by user...")
        exitcode = 6
    except PermissionError:
        logger.critical("File access error. Please do not open or lock an input file while the parser is running.")
        exitcode = 2
    except:
        console(f"Uncaught exception caused {parsers.PROG_NAME_ABBR} to crash.\nException trace has been output to \"{logfile}\"", "Critical Error", "error")
        logger.error("\n" + traceback.format_exc())
        exitcode = 1
    finally:
        if parsers.progress_queue is not None:
            parsers.progress_queue.put({
                "type": "stop"
            })
        logger.info(f"Program terminated with exit code {exitcode}")
        sys.exit(exitcode)