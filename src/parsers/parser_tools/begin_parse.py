# begin_parse.py

import os
import sys
import time
import logging
from multiprocessing import Pool
import threading
import importlib
import parsers
from . import parser_writer
from .toolbox import InputDictKeys, Scanners, select_scanner, console
from .gui.loading_screen import LoadingWindow
from .reporting import Report

logger = logging.getLogger(__name__)

# Multithreading globals
_report = None

def begin(parser_inputs):
    global _report
    
    if len(parser_inputs) <= 0:
        console(f"No inputs defined. Terminating {parsers.PROG_NAME_ABBR}.", 'No Inputs Defined', level='info', orig_name=__name__)
        sys.exit(0)
    
    # Put SRM in the back
    for i, inp in enumerate(parser_inputs, start=0):
        if any(s in inp[InputDictKeys.SCANNER.value].lower().replace(' ', '') for s in Scanners.SRM.keywords):
            parser_inputs.append(parser_inputs.pop(i))
            break
    
    # Assign an input ID for each input
    for i, inp in enumerate(parser_inputs, start=1):
        inp[InputDictKeys.INPUT_ID.value] = f"{i}_{os.path.basename(inp[InputDictKeys.PATH.value])}"
    
    # Init report object
    _report = Report(scanners=[i[InputDictKeys.SCANNER.value] for i in parser_inputs])
    
    # GUI mode
    if parsers.GUI_MODE:
        # Init loading window
        loading_window = LoadingWindow(parsers.gui_root, scanners=[(i[InputDictKeys.SCANNER.value], i[InputDictKeys.PATH.value]) for i in parser_inputs])
        parsers.progress_queue = loading_window.queue
    
        threading.Thread(
            target=run_parsers,
            args=(parser_inputs,),
            daemon=True
        ).start()

        # Loading screen mainloop to wait until the "complete" status type is reached in run_parsers
        parsers.gui_root.wait_window(loading_window.root)
    
        # Handle unclean exit
        if not loading_window.cleanexit:
            sys.exit(0)
    # CLI mode
    else:
        run_parsers(parser_inputs)
    
    # Generate report
    _report.generate_report()
    
    # Final printing if in CLI
    logger.info("Parsing complete!")
    if not parsers.GUI_MODE:
        print("\nParsing complete!")
        if _report.get_total_errors() > 0:
            print(f"Errors have been detected while parsing files. Please see logfile \"{parsers.LOGFILE}\" for more details.")

# Executed in a worker thread in GUI mode or in the main thread in CLI mode
def run_parsers(parser_inputs):
    global _report
    
    with Pool() as pool:
        results = pool.map(parse_input, parser_inputs)
    
    # Merge results
    for result in results:
        parser_writer.write_rows(result['rows'])
        scanner = result['scanner']
        _report.counts[scanner][0] += result['finding_count']
        _report.counts[scanner][1] += result['err_count']
    
    # Write findings to file
    parser_writer.close_writer()


def parse_input(entry):
    fpath = entry[InputDictKeys.PATH.value]
    scanner = entry[InputDictKeys.SCANNER.value]
    substr = entry[InputDictKeys.REMOVE.value]
    prepend = entry[InputDictKeys.PREPEND.value]
    input_id = entry[InputDictKeys.INPUT_ID.value]
    
    path = os.path.realpath(fpath)
    
    # Put out message early in case loading screen hangs on large inputs or .fpr files
    if parsers.GUI_MODE:
        parsers.progress_queue.put({
            "type": "progress",
            "id": input_id,
            "status": f"Parsing {os.path.basename(fpath)}",
            "percent": 0
        })
    
    selected_scanner = select_scanner(scanner)
    if selected_scanner is None:
        # Scanner not supported
        logger.error("Unsupported scanner. Skipped %s, %s", scanner, fpath)
        parsed_results = []
        finding_count = 0
        err_count = 1
    else:
        # Import corresponding module and parse
        module = importlib.import_module(selected_scanner.module)
        parsed_results, finding_count, err_count = module.parse(path, scanner, substr, prepend, input_id)
    
    # Send message that parser is done
    if parsers.GUI_MODE:
        parsers.progress_queue.put({
            "type": "complete",
            "id": input_id
        })
    
    return {
        "scanner": scanner,
        "rows": parsed_results,
        "finding_count": finding_count,
        "err_count": err_count,
    }
    
