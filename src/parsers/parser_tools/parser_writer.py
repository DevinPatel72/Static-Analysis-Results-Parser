# parser_writer.py

import os
import csv
import time
import logging
from .toolbox import check_all_CWEs, format_time
from .preflight import apply_prules
from .dupe_scan_consolidation import dupe_scan_consolidation

logger = logging.getLogger(__name__)
__excel_enabled = False

try:
    import openpyxl
    __excel_enabled = True
except ImportError:
    __excel_enabled = False

__filepath = None
__parser_data = []
__excel_workbook = None
__fieldnames = None

def open_writer(outfile, fieldnames, sheet_name='Sheet1', force_csv=False):
    global __filepath, __excel_workbook, __fieldnames, __excel_enabled
    from parsers import GUI_MODE
    
    __fieldnames = fieldnames
    elapsed_time = -1
    
    # Update the boolean to include whether the user requests CSV
    __excel_enabled = __excel_enabled and not force_csv
    
    while True:
        # Attempt to open file
        try:
            if __excel_enabled:
                if os.path.splitext(outfile)[1] != '.xlsx':
                    outfile = os.path.splitext(outfile)[0] + '.xlsx'
                __filepath = outfile
                __excel_workbook = openpyxl.Workbook()
                temp = __excel_workbook.active
                temp.title = sheet_name
                temp.append([header for header in __fieldnames])
            else:
                if os.path.splitext(outfile)[1] != '.csv':
                    outfile = os.path.splitext(outfile)[0] + '.csv'
                __filepath = outfile
            break
        except PermissionError:
            if GUI_MODE:
                from tkinter import messagebox
                messagebox.showerror("Unable to open file", f"File \"{outfile}\" cannot be opened.\n\nTo continue, please make sure the file is not already open in another program.")
            else:
                if elapsed_time < 0:
                    print(f"Output file \"{outfile}\" cannot be opened. To continue, please make sure the file is not already open in another program.")
                    elapsed_time = 0
                print('Waiting: ' + format_time(elapsed_time), end='\r')
                time.sleep(1)
                elapsed_time += 1
    if not GUI_MODE and elapsed_time >= 0:
        print()
                
            
def write_row(r):
    global __parser_data
    __parser_data.append(r)
        
def search_row(tuples, skip_ids=''):
    """
    Searches existing rows for parsed findings.
    
    :param tuples: List of tuples with format (Fieldnames.[Header].value, keyword, exact_str_match=[True|False])
    :param skip_ids: List of string IDs to skip over when searching
    :return: First row that matches, otherwise None.
    """
    global __parser_data
    from .toolbox import Fieldnames
    for row in __parser_data:
        matches = []
        # Skip id's
        if (len(skip_ids) > 0 and row[Fieldnames.ID.value] in skip_ids):
            continue
        for header, keyword, exact_str_match in tuples:
            lookup = row.get(header, '')
        
            # First check for NULL
            if lookup is not None:
                # If string, check for length and if keyword is contained in lookup
                if isinstance(lookup, str) and len(lookup) > 0:
                    if exact_str_match:
                        matches.append(str(keyword) == lookup)
                    else: matches.append(str(keyword).lower() in lookup.lower())
                
                # If integer, check for exact match
                elif isinstance(lookup, int):
                    try:
                        matches.append(int(keyword) == lookup)
                    except ValueError:
                        logger.error(f"Invalid search lookup. Expected integer input, got string \"{keyword}\"")
                        matches.append(False)
                        break
                
                else:
                    matches.append(keyword == lookup)
                    break
        if all(matches):
            return {
                Fieldnames.SCORING_BASIS.value: row[Fieldnames.SCORING_BASIS.value],
                Fieldnames.CONFIDENCE.value: row[Fieldnames.CONFIDENCE.value],
                Fieldnames.MATURITY.value: row[Fieldnames.MATURITY.value],
                Fieldnames.MITIGATION.value: row[Fieldnames.MITIGATION.value],
                Fieldnames.PROPOSED_MITIGATION.value: row[Fieldnames.PROPOSED_MITIGATION.value],
                Fieldnames.VALIDATOR_COMMENT.value: row[Fieldnames.VALIDATOR_COMMENT.value],
                Fieldnames.ID.value: row[Fieldnames.ID.value]
            }
    return None
        

def close_writer():
    global __filepath, __excel_workbook, __fieldnames, __excel_enabled, __parser_data
    from parsers import GUI_MODE
    
    elapsed_time = -1
    
    # Post-processing of data
    if len(__parser_data) > 0:
        
        # Duplicate Scanner Consolidation
        dupes_count = dupe_scan_consolidation(__parser_data)
        if dupes_count >= 0:
            logger.info(f"Discovered {dupes_count} duplicate findings")
        
        # Perform preflighting
        apply_prules(__parser_data)
        
        # Check for CWE category mappings
        check_all_CWEs(__parser_data)
        
        # Write out parser data to file
        if __filepath is not None:
            if __excel_enabled:
                while True:
                    try:
                        temp = __excel_workbook.active
                        for r in __parser_data: temp.append([r.get(header, '') for header in __fieldnames])
                        __excel_workbook.save(__filepath)
                        break
                    except PermissionError:
                        if GUI_MODE:
                            from tkinter import messagebox
                            messagebox.showerror("Unable to open file", f"File \"{__filepath}\" cannot be opened.\n\nTo continue, please make sure the file is not already open in another program.")
                        else:
                            if elapsed_time < 0:
                                print(f"Output file \"{__filepath}\" cannot be opened. To continue, please make sure the file is not already open in another program.")
                                elapsed_time = 0
                            print('Waiting: ' + format_time(elapsed_time), end='\r')
                            time.sleep(1)
                            elapsed_time += 1
            else:
                with open(__filepath, 'w', newline='', encoding='utf-8-sig') as o:
                    csv_writer = csv.DictWriter(o, fieldnames=__fieldnames)
                    csv_writer.writeheader()
                    csv_writer.writerows(__parser_data)

    if not GUI_MODE and elapsed_time >= 0:
        print()
    
    __filepath = None
