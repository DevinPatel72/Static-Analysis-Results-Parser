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
from parsers.parser_tools.toolbox import InputDictKeys, InputConfigFlags, Fieldnames, load_config_user_inputs, load_config_cwe_category_mappings, export_config, check_input_format, print_user_inputs_template, dedupe_parser_inputs
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

# Check if matplotlib is installed. Logged here to ensure correct placement in log file
if find_spec('matplotlib') is None:
    logger.warning(f'Module \'matplotlib\' not found, {parsers.PROG_NAME_ABBR} will skip chart reporting.')
    # Handled in reporting.py

################################
# Functions
################################

def print_inputs(parser_inputs, parser_outfile, control_flags):
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
    
    # Log the configuration
    logger.info("\n".join(['    ' + l for l in s.split('\n')]))

def print_inputs_file_list():
    for i in sorted(os.listdir(parsers.INPUTS_DIR),
                        key=lambda s: ( # Lambda function for natural key sort
                        (m := __import__("re").match(r"^(.*?)(?:-(\d+))?(\.[^.]+)$", s))[1].lower(),
                        0 if m[2] is None else 1,
                        int(m[2] or 0)
    )):
        print(i.replace('.json', ''))

def print_inputs_file_contents(fpath):
    rv = load_config_user_inputs(fpath)
    if isinstance(rv, str):
        logger.critical(f"Unable to open inputs: {rv}")
        sys.exit(3)
    else:
        parser_inputs, parser_outfile, control_flags = rv
        print_inputs(parser_inputs, parser_outfile, control_flags)

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
    argparser.add_argument('-i', '--input', action="append", nargs=2, metavar=("SCANNER", "FILE"), help="Add a scanner input using a scanner name and a path to the corresponding results file. Can be specified multiple times. Used in addition to a `--file` input if present.\nExample: -i Fortify \"path/to/file.fpr\" -i Coverity \"path/to/file.json\"")
    argparser.add_argument('-I', '--extended-input', action="append", dest="extended_input", nargs=4, metavar=("SCANNER", "FILE", "REMOVE", "PREPEND"), help="Add a scanner input with path transformation settings. Accepts scanner name, file path, path prefix to remove, and path prefix to prepend. Can be specified multiple times. Used in addition to a `--file` input if present.\nExample: -I Fortify \"path/to/file.fpr\" \"remove_from_path_value\" \"prepend_to_path_value\" -I Coverity \"path/to/file.json\" \"use_empty_quotes_for_blank\" \"\"")
    argparser.add_argument('-f', '--file', type=str, default="", help="Load a user inputs JSON configuration file. Accepts either an absolute path or a filename located in the `config/inputs` directory. Defaults to `config/inputs/{}_inputs.json` if no input options are specified.".format(parsers.PROG_NAME_ABBR.lower()))
    argparser.add_argument('-o', '--out', type=str, help='Output file path. Overrides the output path specified in a `--file` input. If not specified, the current working directory is used.')
    argparser.add_argument('-pn', '--project-name', dest="projectname", help="Specify the project name to include in generated reports.")
    argparser.add_argument('-pv', '--project-version', dest="projectversion", help="Specify the project version to include in generated reports.")
    
    for f in InputConfigFlags:
        # Default value is True
        if f.default:
            argparser.add_argument(
                f"--no-{f.flag.lower().replace(' ', '-')}",
                dest=f.flag.lower().replace(' ', '-'),
                action="store_false",
                default=None,
                help=f"Disable {f.flag}. Overrides the flag value specified in a `--file`."
            )
        else:
            argparser.add_argument(
                f"--{f.flag.lower().replace(' ', '-')}",
                dest=f.flag.lower().replace(' ', '-'),
                action="store_true",
                default=None,
                help=f"Enable {f.flag}. Overrides the flag value specified in a `--file`."
            )
    
    argparser.add_argument('-c', '--check-inputs', dest="checkinputs", action='store_true', help="Validate the user inputs JSON file specified by `--file`, report any errors, and exit.")
    argparser.add_argument('-l', '--list-inputs', dest="listinputs", metavar="CONFIG_FILE", nargs='?', const=True, default=False, help="List available input config files in the `inputs` directory. If `CONFIG_FILE` (file name or path) is provided, display that file's contents instead.")
    argparser.add_argument('-s', '--save-config', dest="save_config", metavar="SAVE_NAME", nargs='?', const=True, default=False, help="Save the current command-line inputs to a configuration file. If `SAVE_NAME` is provided, save to the `inputs` directory using that name. If not, overwrite the file specified by `--file` or create a new configuration file.")
    argparser.add_argument('--example-template', dest="exampletemplate", action='store_true', help="Print an example user inputs JSON template and exit.")
    argparser.add_argument('--disable-progressbar', dest="disableprogressbar", action='store_true', help="Disables progress bar in CLI for faster performance.")
    
    args = argparser.parse_args()
    
    # Parse args
    if args.version:
        print(f"{PROG_NAME} {VERSION}")
        sys.exit(0)
    
    # Print user inputs template
    if args.exampletemplate:
        print_user_inputs_template()
        sys.exit(0)
    
    # Print list of input files
    if args.listinputs is True:
        print_inputs_file_list()
        sys.exit(0)
    
    # Print input file contents
    if isinstance(args.listinputs, str):
        if not ('/' in args.listinputs or '\\' in args.listinputs):
            fname = args.listinputs + '.json' if not args.listinputs.endswith('.json') else args.listinputs
            fpath = os.path.join(parsers.INPUTS_DIR, fname)
        else:
            fpath = args.listinputs
        print_inputs_file_contents(fpath)
        sys.exit(0)
    
    # Use file arg if it is passed. If not, check if any input args have been passed. If no input args, then use default <PROG_NAME_ABBR>_inputs.json path. If there are input args, set to blank string so those inputs can be parsed.
    if len(args.file) > 0:
        # Adjust inputs path according to whether it is a basename or a path
        if not ('/' in args.file or '\\' in args.file):
            fname = args.file + '.json' if not args.file.endswith('.json') else args.file
            inp_path = os.path.join(parsers.INPUTS_DIR, fname)
        else:
            inp_path = args.file
    elif args.input is None and args.extended_input is None:
        inp_path = os.path.join(parsers.INPUTS_DIR, parsers.PROG_NAME_ABBR.lower()+'_inputs.json')
    else:
        inp_path = ""
    
    # Load inputs from config file
    rv = load_config_user_inputs(inp_path, default_outfile=f"{parsers.PROG_NAME_ABBR.lower()}_output.xlsx", default_control_flags=control_flags)
    if isinstance(rv, str):
        logger.critical(f"Unable to open inputs: {rv}")
        sys.exit(3)
    else:
        parser_inputs, parser_outfile, control_flags = rv
    
    # Override outfile if the arg was passed
    if args.out is not None and len(args.out) > 0:
        parser_outfile = args.out
    
    # Override Project name + version if those args were passed
    if args.projectname is not None and len(args.projectname) > 0:
        parsers.PROJ_NAME = args.projectname
    if args.projectversion is not None and len(args.projectversion) > 0:
        parsers.PROJ_VERSION = args.projectversion
        
    # Command line inputs
    if args.input is not None:
        for inp in args.input:
            parser_inputs.append({InputDictKeys.SCANNER.value: inp[0],
                                InputDictKeys.PATH.value: inp[1],
                                InputDictKeys.REMOVE.value: "",
                                InputDictKeys.PREPEND.value: "",
            })
    if args.extended_input is not None:
        for inp in args.extended_input:
            parser_inputs.append({InputDictKeys.SCANNER.value: inp[0],
                                InputDictKeys.PATH.value: inp[1],
                                InputDictKeys.REMOVE.value: inp[2],
                                InputDictKeys.PREPEND.value: inp[3],
            })
    
    if args.disableprogressbar is not None and args.disableprogressbar:
        from parsers.parser_tools import progressbar
        progressbar.DISABLE_PROGRESS_BAR = True
    
    # Control flags
    for f in InputConfigFlags:
        # Fill in any empty control flags with default value
        if f.flag not in control_flags.keys():
            control_flags[f.flag] = f.default
        
        # Check if argument was passed and overwrite what is there
        if (value := getattr(args, f.flag.lower().replace(' ', '-'))) is not None:
            control_flags[f.flag] = value
    
    # Check inputs format
    if len(parser_inputs) > 0:
        # Dedupe parser_inputs
        parser_inputs = dedupe_parser_inputs(parser_inputs)
        
        # Return value is true for success
        rv = check_input_format(parser_inputs, parser_outfile, control_flags)
        
        if rv and args.checkinputs:
            logger.info("[PASS] Inputs are valid")
            print("\n[PASS] Inputs are valid")
            sys.exit(0)
        elif not rv:
            sys.exit(2)
    else:
        logger.info(f"No inputs defined. Terminating {parsers.PROG_NAME_ABBR}...")
        print(f"No inputs defined. Terminating {parsers.PROG_NAME_ABBR}...")
        sys.exit(0)

    # Output confirmation
    print_inputs(parser_inputs, parser_outfile, control_flags)
    
    # Export parser inputs to config file for reruns
    if args.save_config is not False:
        if isinstance(args.save_config, str):
            basename = args.save_config+'.json' if not args.save_config.endswith('.json') else args.save_config
            parsers.INPUTS_PATH = os.path.join(parsers.INPUTS_DIR, basename)
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
    if control_flags[InputConfigFlags.OVERRIDE_VULN_MAPPING.flag]:
        parsers.cwe_categories = load_config_cwe_category_mappings()

    # Init the outfile
    if parser_outfile.lower().endswith('.csv'):
        force_csv = True
    else:
        force_csv = False
    parser_writer.open_writer(parser_outfile, Fieldnames.HEADERS.value, force_csv=force_csv)
    
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
        logger.critical(f"Uncaught exception caused {parsers.PROG_NAME_ABBR} to crash. Exception trace has been output to the logfile.")
        logger.error("\n" + traceback.format_exc())
        exitcode = 1
    finally:
        logger.info(f"Program terminated with exit code {exitcode}")
        print()
        sys.exit(exitcode)
