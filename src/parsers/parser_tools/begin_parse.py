# begin_parse.py

import os
import sys
import time
import logging
import threading
import parsers
from parsers import *
from . import parser_writer
from .toolbox import InputDictKeys
from .loading_screen import LoadingWindow
from .reporting import Report

logger = logging.getLogger(__name__)

# Multithreading globals
_report = None

def begin(parser_inputs):
    global _report
    
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
    logger.info(f"Parsing complete!")
    if not parsers.GUI_MODE:
        print(f"\nParsing complete!")
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
        
        scan_match = scanner.lower().replace(' ', '')
        path = os.path.realpath(fpath)
        
        t_finding_count = 0
        t_err_count = 0
        if any(s in scan_match for s in parsers.aio_keywords):
            t_finding_count, t_err_count = aio.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.xmarx_keywords):
            t_finding_count, t_err_count = checkmarx.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.coverity_keywords):
            t_finding_count, t_err_count = coverity.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.cppcheck_keywords):
            t_finding_count, t_err_count = cppcheck.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.depcheck_keywords):
            t_finding_count, t_err_count = owasp_depcheck.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.eslint_keywords):
            t_finding_count, t_err_count = eslint.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.manualcve_keywords):
            t_finding_count, t_err_count = manual_cve.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.gnatsas_keywords):
            t_finding_count, t_err_count = gnatsas.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.fortify_keywords):
            t_finding_count, t_err_count = fortify.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.pragmatic_keywords):
            t_finding_count, t_err_count = pragmatic.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.pylint_keywords):
            t_finding_count, t_err_count = pylint.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.semgrep_keywords):
            t_finding_count, t_err_count = semgrep.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.sigasi_keywords):
            t_finding_count, t_err_count = sigasi.parse(path, scanner, substr, prepend)
        elif any(s in scan_match for s in parsers.srm_keywords):
            t_finding_count, t_err_count = srm.parse(path, scanner, substr, prepend)
        else:
            logger.error(f"Unsupported scanner. Skipped {fpath},{scanner}")
            t_finding_count = 0
            t_err_count = 1
        
        _report.counts[scanner][0] += t_finding_count
        _report.counts[scanner][1] += t_err_count
        
        if parsers.GUI_MODE:
            time.sleep(0.3)
    
    parser_writer.close_writer()

    # Send message to main thread that parsing is done
    if parsers.GUI_MODE:
        parsers.progress_queue.put({
            "type": "complete"
        })
