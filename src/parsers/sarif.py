# sarif.py

import re
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
    from parsers import PROG_NAME_ABBR
    console(f"{PROG_NAME_ABBR} cannot currently parse SARIF results. Skipping SARIF input.", "SARIF not supported", type='warning')
    return 0, 0
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
    # Get list of scanners
    runs = {}
    
    # Prep the results and rules
    for row in data:
        scanner = row[Fieldnames.SCANNER.value]
        selected_scanner = select_scanner(scanner)
        if selected_scanner == Scanners.SRM:
            selected_scanner = select_scanner(row[Fieldnames.TOOL.value])
        
        if scanner not in runs:
            runs[scanner] = {
                "tool": {
                    "driver": {
                        "name": scanner,
                        "rules": []
                    }
                },
                "results": [],
                "_rules": {}
            }
        
        run = runs[scanner]
        
        # Get rule
        rule_id = row[Fieldnames.TYPE.value]
        if rule_id not in run['_rules']:
            rule = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": rule_id
                }
            }
            run['_rules'][rule_id] = rule
            run["tool"]["driver"]["rules"].append(rule)

        # Get result
        result = {
            "ruleId": rule_id,
            "message": {
                "text": row[Fieldnames.MESSAGE.value]
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": row[Fieldnames.PATH.value]
                    },
                    "region": {
                        "startLine": row[Fieldnames.LINE.value]
                    }
                }
            }],
            "partialFingerprints": {
                "findingId": row[Fieldnames.ID.value]
            },
            "properties": {
                Fieldnames.CONFIDENCE.value.lower(): row[Fieldnames.CONFIDENCE.value],
                Fieldnames.MATURITY.value.lower().replace(' ', '_'): row[Fieldnames.MATURITY.value],
                Fieldnames.MITIGATION.value.lower().replace(' ', '_'): row[Fieldnames.MITIGATION.value],
                Fieldnames.PROPOSED_MITIGATION.value.lower().replace(' ', '_'): row[Fieldnames.PROPOSED_MITIGATION.value],
                Fieldnames.VALIDATOR_COMMENT.value.lower().replace(' ', '_'): row[Fieldnames.VALIDATOR_COMMENT.value],
                Fieldnames.LANGUAGE.value.lower().replace(' ', '_'): row[Fieldnames.LANGUAGE.value],
                Fieldnames.SYMBOL.value.lower().replace(' ', '_'): row[Fieldnames.SYMBOL.value],
                Fieldnames.SEVERITY.value.lower().replace(' ', '_'): row[Fieldnames.SEVERITY.value]
            }
        }
        
        severity = _severity_remap(row[Fieldnames.SEVERITY.value], selected_scanner)
        if len(severity) > 0:
            result['level'] = severity
        
        # Trace
        if len(row[Fieldnames.TRACE.value]) > 0:
            trace = row[Fieldnames.TRACE.value].strip().split('\n')
            locations = []
            for t in trace:
                t = t.strip()
                if len(t) <= 0:
                    continue
                
                # Extract path, line, and message from trace entry
                if (m := re.match(r"^\d+\) (.*?):(\d+)(?::(.*))?$", t)):
                    path = m.group(1)
                    line = int(m.group(2))
                    msg = m.group(3) if m.group(3) is not None else ""
                else:
                    path = line = msg = ""
                
                # Creation location object
                location = {}

                if len(msg) > 0:
                    location["message"] = {"text": msg.strip()}

                if len(path) > 0:
                    location["physicalLocation"] = {
                        "artifactLocation": {
                            "uri": path
                        }
                    }

                    if isinstance(line, int) or len(line) > 0:
                        location["physicalLocation"]["region"] = {
                            "startLine": int(line) if str(line).isdigit() else line
                        }

                locations.append({
                    "location": location
                })
            
            if len(locations) > 0:
                result["codeFlows"] = [{
                    "threadFlows": [{
                        "locations": locations
                    }]
                }]
        
        # Scanner-specific properties
        if selected_scanner in [Scanners.DEP_CHECK, Scanners.NVD_CVE]:
            result['properties']['cve'] = row[Fieldnames.SCORING_BASIS.value]
            result['properties']['tool_cwe'] = row[Fieldnames.TOOL_CWE.value]
        # Remaining scanners
        else:
            result['properties']['cwe'] = row[Fieldnames.SCORING_BASIS.value]
            result['properties']['tool_cwe'] = row[Fieldnames.TOOL_CWE.value]

        run["results"].append(result)

    for run in runs.values():
        del run['_rules']

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": list(runs.values())
    }
    
    return sarif
    
