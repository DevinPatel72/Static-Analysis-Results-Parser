#!/usr/bin/env python3

# Imports
import os
import sys
import traceback
import parsers
import tkinter as tk
from parsers.parser_tools.toolbox import InputDictKeys, InputConfigFlags, Fieldnames, console, load_config_cwe_category_mappings, export_config
from parsers.parser_tools import parser_writer, preflight
import parsers.parser_tools.progressbar as progressbar
from parsers.parser_tools.begin_parse import begin
from parsers.parser_tools.gui.app_controller import SARPApp
from update import check_version

# Init GUI
parsers.gui_root = tk.Tk()
parsers.gui_root.withdraw()
parsers.GUI_MODE = True
progressbar.DISABLE_PROGRESS_BAR = True

# Configure root path and important dirs of script
if getattr(sys, 'frozen', False):
    # Running as bundled executable
    parsers.EXE_ROOT_DIR = os.path.dirname(sys.executable)
    logname = os.path.splitext(os.path.basename(sys.executable))[0]+'.log'
    parsers.ASSETS_DIR = os.path.join(sys._MEIPASS, parsers.ASSETS_DIR)
    parsers.LOGO_PATH = os.path.join(parsers.ASSETS_DIR, 'logos', 'sarp-logo-256.png')
    if not os.path.isfile(parsers.LOGO_PATH):
        parsers.LOGO_PATH = os.path.join(parsers.ASSETS_DIR, 'logos', 'sarp-logo-1024.png')
else:
    # Running as script
    parsers.EXE_ROOT_DIR = os.path.dirname(__file__)
    logname = os.path.splitext(os.path.basename(__file__))[0]+'.log'
    parsers.ASSETS_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.ASSETS_DIR)
    parsers.LOGO_PATH = os.path.join(parsers.ASSETS_DIR, 'logos', 'sarp-logo-256.png')
    if not os.path.isfile(parsers.LOGO_PATH):
        parsers.LOGO_PATH = os.path.join(parsers.ASSETS_DIR, 'logos', 'sarp-logo-1024.png')

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
logger.info("%s %s", parsers.PROG_NAME, parsers.VERSION)
logger.info(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# Check if openpyxl is installed. Logged here to ensure correct placement in log file
from importlib.util import find_spec
if find_spec('openpyxl') is None:
    logger.warning('Module \'openpyxl\' not found, defaulting output to CSV.')
    # Handled in parser_writer.py

# Check if matplotlib is installed. Logged here to ensure correct placement in log file
if find_spec('matplotlib') is None:
    logger.warning('Module \'matplotlib\' not found, %s will skip chart reporting.', parsers.PROG_NAME_ABBR)
    # Handled in reporting.py

################################
# Main
################################

def main():
    # Check for updates first
    rv = check_version(parsers.VERSION)
    if rv is not None and isinstance(rv, str) and len(rv) > 0:
        console(f'A new version of {parsers.PROG_NAME_ABBR} is available. To upgrade to {rv}, run the update executable.', 'New Version Available', type='info', orig_name=__name__)
    
    parser_inputs = []
    parser_outfile = ""
    control_flags = {}
    
    app = SARPApp()
    
    parser_inputs = app.parser_inputs
    parser_outfile = app.parser_outfile
    control_flags = app.control_flags
    
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
    if app.select_input is None:
        no_overwrite = False
    else: no_overwrite = not (app.select_input.results is not None and len(app.select_input.results) > 0)
    export_config(parser_inputs, parser_outfile, control_flags, no_overwrite=no_overwrite)
    
    # Save the preflight rules
    preflight.save_prules(parsers.prules)
    
    # Load the mapping if true
    if control_flags[InputConfigFlags.OVERRIDE_VULN_MAPPING.flag]:
        parsers.cwe_categories = load_config_cwe_category_mappings()
    
    # Put control_flags into module variable
    parsers.control_flags = control_flags

    # Init the outfile
    force_csv = parser_outfile.lower().endswith('.csv')
    force_sarif = parser_outfile.lower().endswith(('.sarif', '.json'))
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
        console(f"Uncaught exception caused {parsers.PROG_NAME_ABBR} to crash.\nException trace has been output to \"{logfile}\"", "Critical Error", "error", orig_name=__name__)
        logger.error("\n%s", traceback.format_exc())
        exitcode = 1
    finally:
        if parsers.progress_queue is not None:
            parsers.progress_queue.put({
                "type": "stop"
            })
        logger.info("Program terminated with exit code %d", exitcode)
        sys.exit(exitcode)