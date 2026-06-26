# sarif.py

import os
import logging
import traceback
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames, console


logger = logging.getLogger(__name__)

pylint_cdata = {}

def path_preview(fpath):
    # No preview available
    return 'No preview available for SARIF'
    

# Entrypoint to this module
def parse(fpath=None, scanner=None, substr=None, prepend=None, p_sarif_data=None):
    sarif_data = p_sarif_data
    excel_data = []
    
    # Count findings and errors encountered while running
    finding_count = 0
    err_count = 0
    
    # If SARIF input is coming from a file, load it into sarif_data
    try:
        if not (fpath is None or scanner is None or substr is None or prepend is None):
            with open(fpath, mode='r', encoding='utf-8-sig') as r:
                sarif_data = json.load(r)
            logger.info(f"Parsing {scanner} - {fpath}")
    except:
        logger.error(f"File \'{fpath}\' failed to open:\n{traceback.format_exc()}")
        return finding_count, err_count + 1
    
    # If sarif_data is still None, throw an error and return an empty list of rows
    if sarif_data is None:
        logger.warning('No sarif data to be parsed')
        return excel_data
    

    
    
