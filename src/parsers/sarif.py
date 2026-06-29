# sarif.py

import os
import logging
import traceback
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames, Scanners, select_scanner, console


logger = logging.getLogger(__name__)

# Remaps all known severity values to keywords supported by SARIF standard
def _severity_remap(severity, scanner_type, default=''):
    return scanner_type.severity_map.get(str(severity).lower(), default)

def path_preview(fpath):
    # TODO No preview available for now
    return 'No preview available for SARIF'
    

# This function converts a SARIF data structure to an Excel one
def parse(fpath, scanner, substr, prepend):
    sarif_data = None
    excel_data = []
    
    # Count findings and errors encountered while running
    finding_count = 0
    err_count = 0
    
    # If SARIF input is coming from a file, load it into sarif_data
    try:
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
    
# Converts list of dictionaries to SARIF format
def rows_to_sarif(data):
    results = []
    for row in data:
        selected_scanner = select_scanner(row[Fieldnames.SCANNER.value])
        if selected_scanner == Scanners.SRM:
            selected_scanner = select_scanner(row[Fieldnames.TOOL.value])

        result = {
            "ruleId": row[Fieldnames.TYPE.value],
            "message": {
                "text": row[Fieldnames.MESSAGE.value]
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": path
                    },
                    "region": {
                        "startLine": line
                    }
                }
            }],
            "partialFingerprints": {
                "findingId": id
            },
            "properties": {
                "cwe": tool_cwe,
                "language": "python"
            }
        }
        
        severity = _severity_remap(row[Fieldnames.SEVERITY.value], selected_scanner)
        if len(severity) > 0:
            result['level'] = severity

        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": scanner,
                    "rules": rules
                }
            },
            "results": results
        }]
    }    
    
