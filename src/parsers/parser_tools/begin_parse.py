# begin_parse.py

import os
import sys
import time
import logging
import threading
import importlib
import parsers
from . import parser_writer
from .toolbox import InputDictKeys, Scanners, select_scanner
from .loading_screen import LoadingWindow
from .reporting import Report

logger = logging.getLogger(__name__)

# Multithreading globals
_report = None

def begin(parser_inputs):
    global _report
    
    # Put SRM in the back
    for i, inp in enumerate(parser_inputs, start=0):
        if any(s in inp[InputDictKeys.SCANNER.value].lower().replace(' ', '') for s in Scanners.SRM.keywords):
            parser_inputs.append(parser_inputs.pop(i))
            break
    
    # Init report object
    _report = Report(scanners=[i[InputDictKeys.SCANNER.value] for i in parser_inputs])
    
    # GUI mode
    if parsers.GUI_MODE:
        # Init loading window
        loading_window = LoadingWindow()
        parsers.progress_queue = loading_window.queue
    
        threading.Thread(
            target=run_parsers,
            args=(parser_inputs,),
            daemon=True
        ).start()

        # Loading screen mainloop to wait until the "complete" status type is reached in run_parsers
        loading_window.root.mainloop()
    
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
    
    # Parse the inputs
    for entry in parser_inputs:
        fpath = entry[InputDictKeys.PATH.value]
        scanner = entry[InputDictKeys.SCANNER.value]
        substr = entry[InputDictKeys.REMOVE.value]
        prepend = entry[InputDictKeys.PREPEND.value]
        
        # Put out message early in case loading screen hangs on large inputs or .fpr files
        if parsers.GUI_MODE:
            parsers.progress_queue.put({
                "type": "progress",
                "status": f"Parsing {os.path.basename(fpath)}",
                "percent": 0
            })
        
        path = os.path.realpath(fpath)
        
        t_finding_count = 0
        t_err_count = 0
        
        selected_scanner = select_scanner(scanner)
        if selected_scanner is None:
            # Scanner not supported
            logger.error("Unsupported scanner. Skipped %s, %s", scanner, fpath)
            t_finding_count = 0
            t_err_count = 1
        else:
            # Import corresponding module and parse
            module = importlib.import_module(selected_scanner.module)
            t_finding_count, t_err_count = module.parse(path, scanner, substr, prepend)
        
        _report.counts[scanner][0] += t_finding_count
        _report.counts[scanner][1] += t_err_count
        
        if parsers.GUI_MODE:
            time.sleep(0.2)
    
    parser_writer.close_writer()

    # Send message to main thread that parsing is done
    if parsers.GUI_MODE:
        parsers.progress_queue.put({
            "type": "complete"
        })
