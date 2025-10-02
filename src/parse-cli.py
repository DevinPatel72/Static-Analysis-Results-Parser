#!/usr/bin/env python3

from parsers import PROG_NAME, VERSION

print(f"""
#############################################################################################################
# {PROG_NAME} {VERSION}
#
# Please read the readme for further information.
#
# This all-in-one script will parse a list of scanner output files and collect them into one Excel or CSV file.
#
# Accepted Inputs:
#   ->  AIO Parser: .xlsx OR .csv
#   ->  Checkmarx:  Directory of .csv files (Single directory, no recursion)
#   ->  CppCheck:   .xml
#   ->  Coverity:   .json
#   ->  Dep Check:  .csv
#   ->  ESLint:     .json
#   ->  Fortify:    .fpr (preferred) OR .csv
#   ->  Gnat SAS:   .csv
#   ->  NVD CVE:    .csv
#   ->  Pragmatic:  .csv
#   ->  Pylint:     .json
#   ->  SRM:        .xml (preferred) OR .csv
#############################################################################################################
""", end="\n")

# Imports
import os
import sys
import re
import shutil
import traceback
from math import ceil
import parsers
from parsers import *
from parsers.parser_tools import parser_writer
from parsers.parser_tools.toolbox import InputDictKeys, load_config, export_config, validate_path_and_scanner, check_input_format, get_all_previews


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
os.makedirs(parsers.CONFIG_DIR, exist_ok=True)

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
# Globals
################################

previews = {}

################################
# Functions
################################

def listdir(inp):
    # Only 'ls' is entered, use current directory
    if re.search(r'^ls$', inp.lower()):
        items = os.scandir()
    else:
        m = re.match(r'^ls\s((?:[a-zA-Z]:)?[\\/]?(?:[\w .-]+[\\/])*[\w .-]+)$', inp)
        
        if m is not None:
            path = m.group(1)
            
            # Check if entered path exists
            if not os.path.exists(path):
                raise ValueError("Path does not exist")
            
            # Check if entered path is not a dir
            elif not os.path.isdir(path):
                print('\n' + os.path.basename(path) + '\n')
                return
            
            # Else create a list of directory items
            else:
                items = os.scandir(path)
        else:
            raise ValueError("Argument is not a path")
        
    # Pick out directories in the list of items
    s_items = [f"<{i.name}>" if i.is_dir() else i.name for i in items]
    items.close()
      
    # Calculate spacing
    width = shutil.get_terminal_size().columns
    max_len = max(len(item) for item in s_items) + 2
    columns = min(2, max(1, width // max_len))
    rows = ceil(len(s_items) / columns)

    # Print columns in transpose
    print()
    for r in range(rows):
        for c in range(columns):
            i = r + c * rows
            if i < len(s_items):
                print(f"{s_items[i]:<{max_len}}", end=" ")
        print()
    print()
    

def prompt_input_entry():
    def print_help():
        print('\n')
        print("Please specify an input file path and scanner separated by a comma.\n"
        + "E.g.:\n"
        + "    gnatsas-output.csv,Gnat SAS 24.0\n"
        + "    ../../proj1/AIO_parser_output.xlsx,AIO\n"
        + "    \"C:\\Users\\...\\cppcheck-output.xml\",cppcheck\n"
        + "\n"
        + "Use \'ls [dir]\' to see file names\n"
        + "Enter \'q\' to stop adding inputs\n"
        + "Enter \'v\' to see the version of this software\n"
        + "Enter \'h\' to see this help message again")
    print_help()
    
    import csv
    from io import StringIO
    
    # Input loop
    inputs = []
    while True:
        user = input(f"\n[{os.getcwd()}]$ ").strip()
        
        if len(user) <= 0:
            continue
        
        # Help
        if user.lower() == 'h':
            print_help()
            continue
        
        # Version
        if user.lower() == 'v':
            print(f"{PROG_NAME} {VERSION}")
            continue
        
        # Quit
        if user.lower() == 'q':
            if len(inputs) <= 0:
                print("\nNo inputs specified. Terminating script...")
                sys.exit(0)
            else: return inputs
        
        # 'ls' command
        if re.search(r'^ls', user.lower()):
            try:
                listdir(user)
            except ValueError as ve:
                print("\n[ERROR]  Invalid input: {}".format(ve))
            except Exception:
                logger.critical("An unknown exception occurred while running \'ls\'. Its implementation may not be supported on this platform. Exception trace has been output to the logfile.")
                logger.error('\n' + traceback.format_exc())
            continue
                
        # Attempt to parse input
        # Use StringIO to simulate a file for csv.reader, tokenizes user input based on unescaped commas
        with StringIO(user) as f:
            tokens = next(csv.reader(f))
        
        if len(tokens) != 2:
            print("\n[ERROR]  Invalid input: Expected 2 arguments separated by a comma, received {}\n".format(len(tokens)))
            continue
        
        fpath, scanner = tokens
        
        fpath = fpath.replace('\"', '').replace('\'', '')
        scanner = scanner.replace('\"', '').replace('\'', '')
        
        fpath = fpath.strip()
        fpath = fpath[:-1] if fpath.endswith('/') or fpath.endswith('\\') else fpath
        scanner = scanner.strip()
        
        if len(scanner) <= 0:
            print("\n[ERROR]  Invalid input: Missing scanner\n")
            continue
        
        if len(fpath) <= 0:
            print("\n[ERROR]  Invalid input: Missing file path\n")
            continue

        if (msg := validate_path_and_scanner(fpath, scanner)) != 'TRUE':
            print("[ERROR]  " + msg)
            continue
        
        # All checks pass, append input to list of inputs
        inputs.append({InputDictKeys.PATH.value: fpath, InputDictKeys.SCANNER.value: scanner})
        print(f"\n[SUCCESS] Successfully added {fpath},{scanner}")


def prompt_outfile():
    outfile = r""
    while len(outfile) <= 0:
        outfile = input("\nPlease specify the path of the output file [Leave blank for \"AIO_parser_output.xlsx\" in current directory]: ").strip()
        outfile = outfile.replace('\"', '')
        
        # Default is chosen
        if len(outfile) <= 0: outfile = os.path.join(os.getcwd(), "AIO_parser_output.xlsx")
        
        # Check to see if slashes are present, if not, then assume pwd
        elif not ('\\' in outfile or '/' in outfile):
            outfile = os.path.join(os.getcwd(), outfile)
        
        # Else if the directory of the outfile does not exist, ask for input again.
        elif not (os.path.exists(os.path.dirname(outfile)) and os.path.isdir(os.path.dirname(outfile))):
            outfile = ""
            print("[ERROR] Invalid outfile location (You have to prepend \'./\' to place output in a subdirectory of the current working directory)")
            continue
        # Else break out of loop

    return outfile

def prompt_substr(inputs):
    global previews
    new_inputs = []
    print("\nGenerating previews...")
    
    previews = get_all_previews(inputs)
    
    for p, scanner in ((inp[InputDictKeys.PATH.value], inp[InputDictKeys.SCANNER.value]) for inp in inputs):
        scan_match = scanner.lower().replace(' ', '')
        if any(s in scan_match for s in parsers.nopathoverridescanners_keywords):
            new_inputs.append((p, scanner, ''))
            continue
        
        path_preview = fetch_preview(previews[p])
        substr = ""
        while True:
            print(f"\n[{scanner} - {os.path.basename(p)}] Substring to delete from path column (Leave empty to skip deletion)")
            print(f"\nPath Preview: {path_preview}")
            substr = input(">> ").strip()
            
            # Check if the input exists in the path preview
            if substr not in path_preview:
                print("\n[WARNING]  Entered substring does not exist in the path preview. Continue anyways? (y/N)")
                uinput = input(">>> ").strip()
                if uinput.lower() not in ['y', 'yes']:
                    print()
                    continue
            break
        new_inputs.append({InputDictKeys.PATH.value: p, InputDictKeys.SCANNER.value: scanner, InputDictKeys.REMOVE.value: substr})
    
    return new_inputs

def prompt_prepend_str(inputs):
    global previews
    new_inputs = []
    print()
    
    for p, scanner, substr in ((inp[InputDictKeys.PATH.value], inp[InputDictKeys.SCANNER.value], inp[InputDictKeys.REMOVE.value]) for inp in inputs):
        scan_match = scanner.lower().replace(' ', '')
        if any(s in scan_match for s in parsers.nopathoverridescanners_keywords):
            new_inputs.append((p, scanner, substr, ''))
            continue
        print(f"\n[{scanner} - {os.path.basename(p)}] Substring to prepend to path column (Leave empty to skip addition)")
        print('\nPath Preview: {}'.format(fetch_preview(previews[p], remove_substr=substr)))
        prepend = input(">> ")
        new_inputs.append({InputDictKeys.PATH.value: p, InputDictKeys.SCANNER.value: scanner, InputDictKeys.REMOVE.value: substr, InputDictKeys.PREPEND.value: prepend})
    
    return new_inputs

def prompt_control_flags(control_flags):
    
    def ask(prompt_text, default=True):
        y = 'Y' if default else 'y'
        n = 'N' if not default else 'n'
        while True:
            uinput = input(f"\n{prompt_text}\n({y}/{n}): ").strip().lower()
            if len(uinput) == 0:
                return default
            elif uinput in ['y', 'yes', 'yuh', 'uh-huh']: return True
            elif uinput in ['n', 'no', 'nah', 'nuh-uh']: return False
            else:
                print("\n[ERROR]  Invalid input. Please enter yes or no. (Leave blank for {})".format('\"yes\"' if default else '\"no\"'))
    
    control_flags[FLAG_VULN_MAPPING]         = ask("Enable CWE vulnerability mappings? This will append \":CATEGORY\", \":DISCOURAGED\", etc. to the end of CWE numbers.") if FLAG_VULN_MAPPING not in control_flags.keys() else control_flags[FLAG_VULN_MAPPING]
    control_flags[FLAG_OVERRIDE_CWE]         = ask("Enable CWE overrides? This will change the scanner's CWE value to a user-specified value for findings of specific types.") if FLAG_OVERRIDE_CWE not in control_flags.keys() else control_flags[FLAG_OVERRIDE_CWE]
    control_flags[FLAG_OVERRIDE_CONFIDENCE]  = ask("Enable Confidence overrides? This will change the confidence value to a user-specified one for findings of specific types.") if FLAG_OVERRIDE_CONFIDENCE not in control_flags.keys() else control_flags[FLAG_OVERRIDE_CONFIDENCE]
    control_flags[FLAG_FORCE_EXPORT_CSV]     = ask("Force export as CSV? This will ignore the output file extension if yes.", default=False) if FLAG_FORCE_EXPORT_CSV not in control_flags.keys() else control_flags[FLAG_FORCE_EXPORT_CSV]
    
    return control_flags


def fetch_preview(preview, remove_substr='', add_substr=''):
    if remove_substr and remove_substr in preview:
        preview = preview.replace(remove_substr, '', 1)
    
    if add_substr:
        preview = add_substr + preview
    
    return preview


################################
# Main
################################

def main():
    
    parser_inputs = []
    parser_outfile = ""
    control_flags = {}
    
    # Ask user if they wish to load configuration data from file
    if os.path.isfile(os.path.join(parsers.CONFIG_DIR, 'user_inputs.json')):
        while True:
            uinput = input("A user inputs file has been detected. Would you like to load this data?\n(y/n): ")
            
            if len(uinput) <= 0:
                print("\n[ERROR]  Please answer \'y\' or \'n\'", end='\n\n')
                continue
            
            if uinput in ['y', 'yes']:
                # Load inputs from config file
                rv = load_config()
                if isinstance(rv, str):
                    if "Config file \'user_inputs.json\' not found." != rv:
                        logger.warning(f"{rv}")
                        print(f"[WARNING]  {rv}\n{' '*11}Defaulting to using guided prompts.")
                        input("Press Enter to continue...")
                    parser_inputs = []
                    parser_outfile = ""
                    control_flags = {}
                else:
                    parser_inputs, parser_outfile, control_flags = rv
                break
            elif uinput in ['n', 'no']:
                parser_inputs = []
                parser_outfile = ""
                control_flags = {}
                break
            else:
                print("[ERROR]  Please answer \'y\' or \'n\'")
                continue
        
    # Check inputs format
    if len(parser_inputs) > 0:
        check_input_format(parser_inputs, parser_outfile, control_flags)

    # Guided prompts if there are missing inputs
    parser_inputs = prompt_input_entry() if len(parser_inputs) <= 0 else parser_inputs
    parser_inputs = prompt_substr(parser_inputs) if len(list(parser_inputs[0].keys())) <= 2 else parser_inputs
    parser_inputs = prompt_prepend_str(parser_inputs) if len(list(parser_inputs[0].keys())) <= 3 else parser_inputs
    parser_outfile = prompt_outfile() if len(parser_outfile) <= 0 else parser_outfile
    control_flags = prompt_control_flags(control_flags) if len(control_flags) < len(InputDictKeys.FLAGS.value) else control_flags
    
    # Output confirmation
    print('\n#################################################################\n')
    s = "Reading from files:\n"
    for i, inp in enumerate(parser_inputs, 1):
        s += f"{i})  Scanner: {inp[InputDictKeys.SCANNER.value]}\n    Path: {inp[InputDictKeys.PATH.value]}\n    Path substring to delete: {inp[InputDictKeys.REMOVE.value]}\n    Path substring to prepend: {inp[InputDictKeys.PREPEND.value]}\n"
    s += f"\nWriting to file: {parser_outfile}\n"
    s += "\nParser Switches:\n"
    s += "\n".join([f"  Enable {k}:".ljust(34) + f"{v}" for k,v in control_flags.items()]).strip('\n')
    print(s)
    
    # Log the configuration
    logger.info("\n".join(['    ' + l for l in s.split('\n')]))
    
    # Export parser inputs to config file for reruns
    export_config(parser_inputs, parser_outfile, control_flags)
    
    # Pause for user confirmation
    input("\nPress Enter to continue or CTRL+C to quit...")
    print()

    # Init the outfile
    if parser_outfile.lower().endswith('.csv') or control_flags[FLAG_FORCE_EXPORT_CSV]:
        force_csv = True
    else:
        force_csv = False
    parser_writer.open_writer(parser_outfile, parsers.fieldnames, force_csv=force_csv)

    # Track number of errors
    err_count = 0

    # Parse the inputs
    for i in parser_inputs:
        fpath = i[InputDictKeys.PATH.value]
        scanner = i[InputDictKeys.SCANNER.value]
        substr = i[InputDictKeys.REMOVE.value]
        prepend = i[InputDictKeys.PREPEND.value]
        
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
        
        print() # Create a new line after each progressbar
    
    parser_writer.close_writer()
    
    logger.info("Parsing complete!")
    print("Parsing complete!")
    
    if err_count > 0:
        print(f"{err_count} errors have been detected while parsing files. Please see logfile \"{logfile}\" for more details.")

if __name__ == "__main__":
    exitcode = 0
    try:
        main()
    except SystemExit as se:
        exitcode = se.code
    except KeyboardInterrupt:
        print("\n\nScript terminated by user...")
        logger.info("Script terminated by user...")
        exitcode = 0
    except PermissionError:
        logger.critical("File access error. Please do not open or lock an input file while the parser is running.")
        exitcode = 2
    except:
        logger.critical("Uncaught exception caused the script to crash. Exception trace has been output to the logfile.")
        logger.error("\n" + traceback.format_exc())
        exitcode = 1
    finally:
        logger.info(f"Script terminated with exit code {exitcode}")
        print()
        sys.exit(exitcode)
