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


# Imports
import sys
import traceback
from datetime import datetime
import parsers
from parsers.parser_tools.toolbox import InputDictKeys, InputConfigFlags, InputAdditionalOptions, Fieldnames, load_config_cwe_category_mappings, export_config
from parsers.parser_tools import parser_writer, preflight, parser_logger as logger
from parsers.parser_tools.gui.app_controller import close_splash
from parsers.parser_tools.begin_parse import begin
from parsers.initialization import init_globals, init_main_logger
from parsers.parser_tools.gui.app_controller import SARPApp
from update import check_version

################################
# Main
################################

def main():
    init_globals(gui_mode=True)
    init_main_logger()
    
    # Check for updates first
    rv = check_version(parsers.VERSION)
    if rv is not None and isinstance(rv, str) and len(rv) > 0:
        close_splash()
        logger.console(f'A new version of {parsers.PROG_NAME_ABBR} is available. To upgrade to {rv}, run the update executable.', 'New Version Available', level='info')
    
    parser_inputs = []
    parser_outfile = ""
    control_flags = {}
    
    app = SARPApp()
    
    parser_inputs = app.parser_inputs
    parser_outfile = app.parser_outfile
    control_flags = app.control_flags
    additional_options = app.additional_options
    parsers.jobs = additional_options.get(InputAdditionalOptions.JOBS.opt, InputAdditionalOptions.JOBS.default)
    
    # Put control_flags into module variable
    parsers.control_flags = control_flags
    
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
    s += "\nAdditional Options:\n"
    s += "\n".join([f"  {k.capitalize()}:".ljust(42) + f"{v}" for k,v in additional_options.items()]).strip('\n')
    
    logger.info("\n".join(['    ' + l for l in s.split('\n')]))
    
    # Export parser inputs to config file for reruns. If reading from a selected inputs file, overwrite it instead of creating a new file.
    if app.select_input is None:
        no_overwrite = False
    else: no_overwrite = not (app.select_input.results is not None and len(app.select_input.results) > 0)
    export_config(parser_inputs, parser_outfile, control_flags, additional_options, no_overwrite=no_overwrite)
    
    # Save the preflight rules
    preflight.save_prules(parsers.prules)
    
    # Load the mapping if true
    if control_flags[InputConfigFlags.OVERRIDE_VULN_MAPPING.flag]:
        parsers.cwe_categories = load_config_cwe_category_mappings()

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
        logger.console(f"Uncaught exception caused {parsers.PROG_NAME_ABBR} to crash.\nException trace has been output to \"{parsers.LOGFILE}\"", "Critical Error", "error")
        logger.error("\n%s", traceback.format_exc())
        exitcode = 1
    finally:
        if parsers.progress_queue is not None:
            parsers.progress_queue.put({
                "type": "stop"
            })
        logger.info(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logger.info("Program terminated with exit code %d", exitcode)
        logger.close_logger()
        sys.exit(exitcode)