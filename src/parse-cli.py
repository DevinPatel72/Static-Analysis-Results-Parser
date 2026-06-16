#!/usr/bin/env python3

from parsers import PROG_NAME, VERSION

# Imports
import os
import sys
import argparse
import traceback
import parsers
from parsers import *
from parsers.parser_tools import parser_writer, preflight
from parsers.parser_tools.toolbox import InputDictKeys, Fieldnames, load_config_user_inputs, load_config_cwe_category_mappings, export_config, check_input_format, print_user_inputs_template
from parsers.parser_tools.begin_parse import begin

# Configure root path and important dirs of script
if getattr(sys, 'frozen', False):
    # Running as bundled executable
    parsers.EXE_ROOT_DIR = os.path.dirname(sys.executable)
    logname = os.path.splitext(os.path.basename(sys.executable))[0]+'.log'
else:
    # Running as script
    parsers.EXE_ROOT_DIR = os.path.dirname(__file__)
    logname = os.path.splitext(os.path.basename(__file__))[0]+'.log'

# Captialized drive letter if on Windows
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

################################
# Main
################################

def main():
    
    parser_inputs = []
    parser_outfile = ""
    control_flags = {}
    
    help_description = "This software will parse a list of scanner output files and collect them into one Excel or CSV file."
    
    argparser = argparse.ArgumentParser(description=help_description, formatter_class=argparse.RawTextHelpFormatter)
    argparser.add_argument('-v', '--version', action='store_true', help='Print software version and exit')
    argparser.add_argument('-i', '--inputs', type=str, default=os.path.join(parsers.INPUTS_DIR, "user_inputs.json"), help="User inputs JSON file. An absolute path or just the base name can be passed. By default looks for 'user_inputs.json' in config/inputs directory.")
    argparser.add_argument('-o', '--out', type=str, help='Output file path. This option will override what is set in the inputs file, or choose the current directory by default.')
    argparser.add_argument('-c', '--check-inputs', dest="checkinputs", action='store_true', help="Check the user inputs JSON file pointed to by the 'inputs' option for validity, report any errors, then exit.")
    argparser.add_argument('-l', '--list-inputs', dest="listinputs", action='store_true', help="Print current input configuration from the user inputs JSON file pointed to by the 'inputs' option then exit.")
    argparser.add_argument('-pn', '--project-name', dest="projectname", help="Name of the project")
    argparser.add_argument('-pv', '--project-version', dest="projectversion", help="Version of the project")
    argparser.add_argument('--example-template', dest="exampletemplate", action='store_true', help="Print a template of what a user inputs JSON file should contain.")
    
    args = argparser.parse_args()
    
    # Parse args
    if args.version:
        print(f"{PROG_NAME} {VERSION}")
        sys.exit(0)
    
    # Print user inputs template
    if args.exampletemplate:
        print_user_inputs_template()
        sys.exit(0)
    
    # Adjust inputs path according to whether it is a basename or a path
    if not ('/' in args.inputs or '\\' in args.inputs):
        fname = args.inputs + '.json' if not args.inputs.endswith('.json') else args.inputs
        inp_path = os.path.join(parsers.INPUTS_DIR, fname)
    else:
        inp_path = args.inputs
    
    # Load inputs from config file
    rv = load_config_user_inputs(inp_path, default_outfile="sarp_output.xlsx")
    if isinstance(rv, str):
        logger.critical(f"Unable to open inputs: {rv}")
        sys.exit(3)
    else:
        parser_inputs, parser_outfile, control_flags = rv
    
    if args.out is not None and len(args.out) > 0:
        parser_outfile = args.out
    
    # Project name + version
    if args.projectname is not None and len(args.projectname) > 0:
        parsers.PROJ_NAME = args.projectname
    if args.projectversion is not None and len(args.projectversion) > 0:
        parsers.PROJ_VERSION = args.projectversion
        
    # Check inputs format
    if len(parser_inputs) > 0:
        # Return value is true for success
        rv = check_input_format(parser_inputs, parser_outfile, control_flags)
        
        if rv and args.checkinputs:
            logger.info("[PASS] Inputs are valid")
            print("\n[PASS] Inputs are valid")
            sys.exit(0)
        elif not rv:
            sys.exit(2)
    else:
        logger.info("No inputs defined. Terminating script...")
        print("No inputs defined. Terminating script...")
        sys.exit(0)

    # Output confirmation
    if len(parsers.PROJ_NAME) > 0:
        s = f"\nConfiguration for " + " ".join([part for part in [parsers.PROJ_NAME, parsers.PROJ_VERSION]]) + ":\n"
    else:
        s = "\nConfiguration:\n"
    for i, inp in enumerate(parser_inputs, 1):
        s += f"{i})  Scanner: {inp[InputDictKeys.SCANNER.value]}\n    Path: {inp[InputDictKeys.PATH.value]}\n    Path substring to delete: {inp[InputDictKeys.REMOVE.value]}\n    Path substring to prepend: {inp[InputDictKeys.PREPEND.value]}\n"
    s += f"\nWriting to file: {parser_outfile}\n"
    s += "\nParser Switches:\n"
    s += "\n".join([f"  Enable {k}:".ljust(42) + f"{v}" for k,v in control_flags.items()]).strip('\n')
    print(s)
    
    if args.listinputs:
        sys.exit(0)
    
    # Log the configuration
    logger.info("\n".join(['    ' + l for l in s.split('\n')]))
    
    # Export parser inputs to config file for reruns
    export_config(parser_inputs, parser_outfile, control_flags)
    
    print('\n{}\n'.format('#'*90))
    
    # Put control_flags into module variable
    parsers.control_flags = control_flags
    
    # Load preflight rules if true
    if control_flags[FLAG_PREFLIGHT_RULES]:
        preflight.load_prules()
    else:
        parsers.prules = []
        
    # Load the mapping if true
    if control_flags[InputDictKeys.OVERRIDE_VULN_MAPPING.value]:
        parsers.cwe_categories = load_config_cwe_category_mappings()

    # Init the outfile
    if parser_outfile.lower().endswith('.csv'):
        force_csv = True
    else:
        force_csv = False
    parser_writer.open_writer(parser_outfile, Fieldnames.HEADERS.value, force_csv=force_csv)
    
    # Put SRM in the back
    for i, inp in enumerate(parser_inputs, start=0):
        if any(s in inp[InputDictKeys.SCANNER.value].lower().replace(' ', '') for s in parsers.srm_keywords):
            parser_inputs.append(parser_inputs.pop(i))
            break
    
    begin(parser_inputs)


if __name__ == "__main__":
    exitcode = 0
    try:
        main()
    except SystemExit as se:
        exitcode = se.code
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user...")
        logger.info("Program terminated by user...")
        exitcode = 6
    except PermissionError:
        logger.critical("File access error. Please do not open or lock an input file while the parser is running.")
        exitcode = 2
    except:
        logger.critical("Uncaught exception caused SARP to crash. Exception trace has been output to the logfile.")
        logger.error("\n" + traceback.format_exc())
        exitcode = 1
    finally:
        logger.info(f"Program terminated with exit code {exitcode}")
        print()
        sys.exit(exitcode)
