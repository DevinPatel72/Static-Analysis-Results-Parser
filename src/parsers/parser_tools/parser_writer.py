# parser_writer.py

import os
import re
import csv
import time
import json
from itertools import chain
import parsers
from . import parser_logger as logger
from .toolbox import Fieldnames, InputConfigFlags, Scanners, check_all_CWEs, format_time, select_scanner, fix_scanner_name
from .preflight import apply_prules
from .dupe_scan_consolidation import dupe_scan_consolidation

__excel_enabled = False
__export_sarif = False

try:
    import openpyxl
    __excel_enabled = True
except (ImportError, ModuleNotFoundError):
    __excel_enabled = False
    logger.warning('Module \'openpyxl\' not found, defaulting output to CSV.')

__filepath = None
__parser_data = {} # Dictionary of rows keyed by their ID {row['ID']: row}
__duplicate_index = {} # Dictionary of lists containing duplicate rows keyed by PATH, LINE, TYPE, and SCANNER
__excel_workbook = None
__fieldnames = None

def open_writer(outfile, fieldnames, sheet_name='Sheet1', force_csv=False, force_sarif=False):
    global __filepath, __excel_workbook, __fieldnames, __excel_enabled, __export_sarif
    from parsers import GUI_MODE
    
    __fieldnames = fieldnames
    __export_sarif = force_sarif
    
    # Track time for outfile holding
    elapsed_time = -1
    
    # Update the boolean to include whether the user requests CSV
    __excel_enabled = __excel_enabled and not force_csv
    
    while True:
        # Attempt to open file
        try:
            if __export_sarif:
                if not outfile.lower().endswith('.sarif'):
                    outfile = os.path.splitext(outfile)[0] + '.sarif'
            elif __excel_enabled:
                if not outfile.lower().endswith('.xlsx'):
                    outfile = os.path.splitext(outfile)[0] + '.xlsx'
                __excel_workbook = openpyxl.Workbook(write_only=True)
                __excel_workbook.create_sheet(title=sheet_name)
            else:
                if not outfile.lower().endswith('.csv'):
                    outfile = os.path.splitext(outfile)[0] + '.csv'
            __filepath = outfile
            break
        except PermissionError:
            if GUI_MODE:
                from tkinter import messagebox
                messagebox.showerror("Unable to open file", f"File \"{outfile}\" cannot be opened.\n\nTo continue, please make sure the file is not already open in another program.")
            else:
                if elapsed_time < 0:
                    print(f"\n[ERROR]  Output file \"{outfile}\" cannot be opened. To continue, please make sure the file is not already open in another program.")
                    elapsed_time = 0
                print('Waiting for unlock: ' + format_time(elapsed_time), end='\r')
                time.sleep(1)
                elapsed_time += 1
    if not GUI_MODE and elapsed_time >= 0:
        print()

def write_row(r):
    global __parser_data, __duplicate_index
    # Remove any None values
    for k in r.keys():
        if r[k] is None:
            r[k] = ''
    # Add ID row
    __parser_data.setdefault(r[Fieldnames.ID.value], []).append(r)
    
    # Cache for duplicate index
    key = (
        r[Fieldnames.TYPE.value],
        fix_scanner_name(r[Fieldnames.SCANNER.value]),
        r[Fieldnames.PATH.value],
        r[Fieldnames.LINE.value],
    )
    __duplicate_index.setdefault(key, []).append(r)

def write_rows(data):
    for row in data:
        write_row(row)
        
def search_row(search_params, skip_ids='', match_once=False):
    """
    Searches existing rows for parsed findings.
    
    :param tuples: List of tuples with format (Fieldnames.[Header].value, keyword, exact_str_match=[True|False])
    :param skip_ids: Iterable of string IDs to skip over when searching
    :param match_once: True to return only the first match. False to return a list of all matches.
    :return: All rows that match or only the first match, otherwise None.
    """
    global __duplicate_index
    matches = __duplicate_index.get(tuple(search_params.values()), [])
    return matches
    

def update_row(id, updates):
    """
    Searches for the provided ID and updates row data. Updates all findings with the provided ID or just the first match.
    
    :param id: ID of finding(s) to be updated
    :param updates: Dictionary with format {Fieldnames.[Header].value: replacement_def}
    :return: Number of findings that were updated
    """
    global __parser_data
    
    updated_rows_count = 0
    
    # Get rows with corresponding IDs
    rows = __parser_data.get(id, [])
    
    for row in rows:
        # Perform updates
        row.update(updates)
        updated_rows_count += 1
    
    return updated_rows_count

def flatten_data(data):
    return list(chain.from_iterable(data.values()))

def close_writer():
    global __filepath, __excel_workbook, __export_sarif, __fieldnames, __excel_enabled, __parser_data
    from parsers import GUI_MODE
    
    flattened_data = flatten_data(__parser_data)
    
    # Track time for outfile holding
    elapsed_time = -1
    
    # Post-processing of data
    if len(flattened_data) > 0:
        # Set spacing in terminal if in CLI mode
        if not GUI_MODE: print()
        
        # Duplicate Scanner Consolidation
        dupe_scan_consolidation(flattened_data)
        
        # Perform preflighting
        apply_prules(flattened_data)
        
        # Check for CWE category mappings
        check_all_CWEs(flattened_data)
        
        # Write out parser data to file
        if __filepath is not None:
            logger.info("Writing results to file \"%s\"...", __filepath)
            if __export_sarif:
                while True:
                    try:
                        with open(__filepath, 'w', encoding='utf-8-sig') as out:
                            json.dump(rows_to_sarif(flattened_data), out, indent=2)
                        break
                    except PermissionError:
                        if GUI_MODE:
                            from tkinter import messagebox
                            messagebox.showerror("Unable to open file", f"File \"{__filepath}\" cannot be opened.\n\nTo continue, please make sure the file is not already open in another program.")
                        else:
                            if elapsed_time < 0:
                                print(f"\n[ERROR]  Output file \"{__filepath}\" cannot be opened. To continue, please make sure the file is not already open in another program.")
                                elapsed_time = 0
                            print('Waiting for unlock: ' + format_time(elapsed_time), end='\r')
                            time.sleep(1)
                            elapsed_time += 1
            elif __excel_enabled:
                sheet = __excel_workbook.worksheets[0]
                append_func = sheet.append
                headers = tuple(__fieldnames)
                append_func(headers)
                for row in flattened_data:
                    append_func(tuple(row.get(h, "") for h in headers))
                while True:
                    try:
                        __excel_workbook.save(__filepath)
                        break
                    except PermissionError:
                        if GUI_MODE:
                            from tkinter import messagebox
                            messagebox.showerror("Unable to open file", f"File \"{__filepath}\" cannot be opened.\n\nTo continue, please make sure the file is not already open in another program.")
                        else:
                            if elapsed_time < 0:
                                print(f"\n[ERROR]  Output file \"{__filepath}\" cannot be opened. To continue, please make sure the file is not already open in another program.")
                                elapsed_time = 0
                            print('Waiting for unlock: ' + format_time(elapsed_time), end='\r')
                            time.sleep(1)
                            elapsed_time += 1
            else:
                with open(__filepath, 'w', newline='', encoding='utf-8-sig') as o:
                    csv_writer = csv.writer(o)
                    csv_writer.writerow(__fieldnames)
                    csv_writer.writerows((row.get(h, "") for h in __fieldnames) for row in flattened_data)

    if not GUI_MODE and elapsed_time >= 0:
        print()
    
    logger.info("Output saved to %s", __filepath)
    __filepath = None

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
            "fingerprints": {
                "findingId": row[Fieldnames.ID.value]
            },
            "properties": {
                Fieldnames.LANGUAGE.value.lower().replace(' ', '_'): row[Fieldnames.LANGUAGE.value],
                Fieldnames.SYMBOL.value.lower().replace(' ', '_'): row[Fieldnames.SYMBOL.value],
                Fieldnames.SEVERITY.value.lower().replace(' ', '_'): row[Fieldnames.SEVERITY.value]
            } | ({
                Fieldnames.CONFIDENCE.value.lower(): row[Fieldnames.CONFIDENCE.value],
                Fieldnames.MATURITY.value.lower().replace(' ', '_'): row[Fieldnames.MATURITY.value],
                Fieldnames.MITIGATION.value.lower().replace(' ', '_'): row[Fieldnames.MITIGATION.value],
                Fieldnames.PROPOSED_MITIGATION.value.lower().replace(' ', '_'): row[Fieldnames.PROPOSED_MITIGATION.value],
                Fieldnames.VALIDATOR_COMMENT.value.lower().replace(' ', '_'): row[Fieldnames.VALIDATOR_COMMENT.value]
            } if parsers.control_flags[InputConfigFlags.SARIF_STITCH_PROPERTIES.flag] else {}) 
        }
        
        severity = selected_scanner.severity_map.get(str(row[Fieldnames.SEVERITY.value]).lower(), '')
        if len(severity) > 0:
            result['level'] = severity
        
        # Trace
        if Fieldnames.TRACE.value in row.keys() and len(row[Fieldnames.TRACE.value]) > 0:
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
