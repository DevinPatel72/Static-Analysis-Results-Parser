#!/usr/bin/env python3
#
# Copyright (c) 2026 Devin Patel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

# If version option is passed, check for that first to avoid unnecessary imports
import sys
from parsers import PROG_NAME, VERSION
if '-v' in sys.argv or '--version' in sys.argv:
    print(f"{PROG_NAME} {VERSION}")
    sys.exit(0)

# Imports
import os
import argparse
import traceback
from multiprocessing import freeze_support
from datetime import datetime
import parsers
from parsers.parser_tools import progressbar, parser_writer, preflight, parser_logger as logger
from parsers.parser_tools.toolbox import InputDictKeys, InputConfigFlags, InputAdditionalOptions, Fieldnames, load_config_user_inputs, load_config_cwe_category_mappings, export_config, check_input_format, print_user_inputs_template, dedupe_parser_inputs
from parsers.parser_tools.begin_parse import begin
from parsers.initialization import init_globals, init_main_logger


################################
# Functions
################################

def print_inputs(p_parser_inputs, p_parser_outfile, p_control_flags, p_additional_options):
    if len(parsers.PROJ_NAME) > 0:
        s = "\nConfiguration for " + " ".join([parsers.PROJ_NAME, parsers.PROJ_VERSION]) + ":\n"
    else:
        s = "\nConfiguration:\n"
    for i, inp in enumerate(p_parser_inputs, 1):
        s += f"{i})  Scanner: {inp[InputDictKeys.SCANNER.value]}\n    Path: {inp[InputDictKeys.PATH.value]}\n    Path substring to delete: {inp[InputDictKeys.REMOVE.value]}\n    Path substring to prepend: {inp[InputDictKeys.PREPEND.value]}\n"
    s += f"\nWriting to file: {p_parser_outfile}\n"
    s += "\nParser Switches:\n"
    s += "\n".join([f"  Enable {k}:".ljust(42) + f"{v}" for k,v in p_control_flags.items()]).strip('\n')
    s += "\n\nAdditional Options:\n"
    s += "\n".join([f"  {k.capitalize()}:".ljust(42) + f"{v}" for k,v in p_additional_options.items()]).strip('\n')
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
        logger.critical("Unable to open inputs: %s", rv)
        sys.exit(3)
    else:
        t_parser_inputs, t_parser_outfile, t_control_flags, t_options = rv
        print_inputs(t_parser_inputs, t_parser_outfile, t_control_flags, t_options)

################################
# Main
################################

def main():
    init_globals(gui_mode=False, progressbar_space=progressbar.SPACE)
    init_main_logger()
    
    parser_inputs = []
    parser_outfile = ""
    control_flags = {}
    additional_options = {}
    
    help_description = "This software will parse a list of scanner output files and collect them into one Excel, SARIF, or CSV file."
    
    argparser = argparse.ArgumentParser(description=help_description, formatter_class=argparse.RawTextHelpFormatter)
    argparser.add_argument('-v', '--version', action='store_true', help='Print software version and exit')
    argparser.add_argument('-i', '--input', action="append", nargs=2, metavar=("SCANNER", "FILE"), help="Add a scanner input using a scanner name and a path to the corresponding results file. Can be specified multiple times. Used in addition to a `--file` input if present.\nExample: -i Fortify \"path/to/file.fpr\" -i Coverity \"path/to/file.json\"")
    argparser.add_argument('-I', '--extended-input', action="append", dest="extended_input", nargs=4, metavar=("SCANNER", "FILE", "REMOVE", "PREPEND"), help="Add a scanner input with path normalization settings. Accepts scanner name, file path, path prefix to remove, and path prefix to prepend. Can be specified multiple times. Used in addition to a `--file` input if present.\nExample: -I Fortify \"path/to/file.fpr\" \"remove_from_path_value\" \"prepend_to_path_value\" -I Coverity \"path/to/file.json\" \"use_empty_quotes_for_blank\" \"\"")
    argparser.add_argument('-f', '--file', type=str, default="", help="Load an inputs JSON configuration file. Accepts either an absolute path or a filename located in the `config/inputs` directory. Defaults to `config/inputs/{}_inputs.json` if no input options are specified.".format(parsers.PROG_NAME_ABBR.lower()))
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

    for option in InputAdditionalOptions:
        argparser.add_argument(
            f"--{option.opt.lower().replace(' ', '-')}",
            dest=option.opt.lower().replace(' ', '-'),
            type=type(option.default),
            default=None,
            help=option.description
        )
    
    argparser.add_argument('-c', '--check-inputs', dest="checkinputs", action='store_true', help="Validate the inputs JSON file specified by `--file`, report any errors, and exit.")
    argparser.add_argument('-l', '--list-inputs', dest="listinputs", metavar="CONFIG_FILE", nargs='?', const=True, default=False, help="List available input config files in the `inputs` directory. If `CONFIG_FILE` (file name or path) is provided, display that file's contents instead.")
    argparser.add_argument('-s', '--save-config', dest="save_config", metavar="SAVE_NAME", nargs='?', const=True, default=False, help="Save the current command-line inputs to a configuration file. If `SAVE_NAME` is provided, save to the `inputs` directory using that name. If not, overwrite the file specified by `--file` or create a new configuration file.")
    argparser.add_argument('--format', dest="format", type=str, default="", help="Format of output file. Valid options are EXCEL, SARIF, or CSV.")
    argparser.add_argument('--example-template', dest="exampletemplate", action='store_true', help="Print an example inputs JSON template and exit.")
    argparser.add_argument('--disable-progressbar', dest="disableprogressbar", action='store_true', help="Disables progress bar in CLI for faster performance.")
    
    args = argparser.parse_args()
    
    # Parse args
    
    # Print inputs template
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
    
    # Check for updates
    try:
        from update import check_version
        rv = check_version(parsers.VERSION)
        if rv is not None and isinstance(rv, str) and len(rv) > 0:
            logger.console(f'A new version of {parsers.PROG_NAME_ABBR} is available. To upgrade to {rv}, run the update executable.', 'New Version Available', level='info')
    except (ImportError, ModuleNotFoundError) as exc:
        logger.console(f"Missing module \"{exc.name}.\" Skipping check for updates.", "Check For Updates Failed", level='warning')
    
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
        logger.critical("Unable to open inputs: %s", rv)
        sys.exit(3)
    else:
        parser_inputs, parser_outfile, control_flags, additional_options = rv
    
    # Override outfile if the arg was passed
    if args.out is not None and len(args.out) > 0:
        parser_outfile = args.out
    
    # Change format if defined
    if args.format is not None and len(args.format) > 0:
        if args.format.lower() not in ['excel', 'sarif', 'csv']:
            logger.error("Unsupported format %s. Options are EXCEL, SARIF, or CSV.", args.format)
            sys.exit(6)

        match args.format.lower().strip():
            case 'excel':
                parser_outfile = os.path.splitext(parser_outfile)[0] + '.xlsx'
            case 'sarif':
                parser_outfile = os.path.splitext(parser_outfile)[0] + '.sarif'
            case 'csv':
                parser_outfile = os.path.splitext(parser_outfile)[0] + '.csv'
            case _:
                parser_outfile = os.path.splitext(parser_outfile)[0] + '.xlsx'
    
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
        progressbar.DISABLE_PROGRESS_BAR = True
    
    # Control flags
    for f in InputConfigFlags:
        # Fill in any empty control flags with default value
        if f.flag not in control_flags.keys():
            control_flags[f.flag] = f.default
        
        # Check if argument was passed and overwrite what is there
        if (value := getattr(args, f.flag.lower().replace(' ', '-'))) is not None:
            control_flags[f.flag] = value
    
    # Additional options
    for option in InputAdditionalOptions:
        # Fill in any empty options with default value
        if option.opt not in additional_options.keys():
            additional_options[option.opt] = option.default
            
        # Check if argument was passed and overwrite what is there
        if (value := getattr(args, option.opt.lower().replace(' ', '-'))) is not None:
            additional_options[option.opt] = min(value, option.values[1])
    
    # Check inputs format
    if len(parser_inputs) > 0:
        # Dedupe parser_inputs
        parser_inputs = dedupe_parser_inputs(parser_inputs)
        
        # Return value is true for success
        rv = check_input_format(parser_inputs, parser_outfile, control_flags)
        
        if rv and args.checkinputs:
            print("[PASS] Inputs are valid")
            logger.info("[PASS] Inputs are valid")
            sys.exit(0)
        elif not rv:
            sys.exit(2)
    else:
        logger.console(f"No inputs defined. Terminating {parsers.PROG_NAME_ABBR}...", 'No Inputs Defined', level='info')
        sys.exit(0)

    # Put control_flags into module variable
    parsers.control_flags = control_flags
    
    # Put additional_options into module variable
    parsers.additional_options = additional_options

    # Output confirmation
    print_inputs(parser_inputs, parser_outfile, control_flags, additional_options)
    print('\n{}\n'.format('—'*100))
    
    # Export parser inputs to config file for reruns
    if args.save_config is not False:
        if isinstance(args.save_config, str):
            save_filename = args.save_config+'.json' if not args.save_config.endswith('.json') else args.save_config
            # Check if it is a path
            if not ('/' in save_filename or '\\' in save_filename):
                # Truncate name if longer than 255 characters
                save_filename = save_filename[:251]+'.json' if len(save_filename) > 255 else save_filename
                parsers.INPUTS_PATH = os.path.join(parsers.INPUTS_DIR, save_filename)
            else:
                parsers.INPUTS_PATH = save_filename
        export_config(parser_inputs, parser_outfile, control_flags, additional_options)
    
    # Load preflight rules if true
    if control_flags[InputConfigFlags.PREFLIGHT_RULES.flag]:
        preflight.load_prules()
    else:
        parsers.prules = []
        
    # Load the mapping if true
    if control_flags[InputConfigFlags.OVERRIDE_VULN_MAPPING.flag]:
        parsers.cwe_categories = load_config_cwe_category_mappings()

    # Init the outfile
    force_csv = parser_outfile.lower().endswith('.csv')
    force_sarif = parser_outfile.lower().endswith(('.sarif', '.json'))
    parser_writer.open_writer(parser_outfile, Fieldnames.HEADERS.value, sheet_name=f"{parsers.PROJ_NAME} {parsers.PROJ_VERSION}"[:32], force_csv=force_csv, force_sarif=force_sarif)
    begin(parser_inputs)


if __name__ == "__main__":
    freeze_support()
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
        logger.critical("Uncaught exception caused %s to crash. Exception trace has been output to the logfile.", parsers.PROG_NAME_ABBR)
        logger.error("\n%s", traceback.format_exc())
        exitcode = 1
    finally:
        logger.info(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logger.info("Program terminated with exit code %d", exitcode)
        print()
        logger.close_logger()
    sys.exit(exitcode)
