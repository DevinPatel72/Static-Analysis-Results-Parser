# parser_writer.py

import os
import atexit
import csv
import logging

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
    global __filepath, __parser_data, __excel_workbook, __fieldnames, __excel_enabled
    from parsers import GUI_MODE
    
    __fieldnames = fieldnames
    
    while True:
        try:
            # Update the boolean to include whether the user requests CSV
            __excel_enabled = __excel_enabled and not force_csv
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
                input(f"Output file \"{outfile}\" cannot be opened. To continue, please make sure the file is not already open in another program.\nPress Enter to continue...")
            
def write_row(r):
    if __excel_enabled:
        __parser_data.append(r)
    else:
        __parser_data.append(r)
        
def search_row(tuples):
    """
    Searches existing rows for parsed findings.
    
    :param tuples: List of tuples with format (Fieldnames.<Header>.value, keyword, exact_str_match=[True|False])
    :return: ID of the first row that matches, otherwise None.
    """
    for row in __parser_data:
        matches = []
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
                    matches.append(False)
                    break
        if all(matches):
            return row.get('ID', None)
    return None
        

@atexit.register
def close_writer():
    global __filepath
    if __filepath is not None:
        from parsers import GUI_MODE
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
                        input(f"Output file \"{__filepath}\" cannot be opened. To continue, please make sure the file is not already open in another program.\nPress Enter to continue...")
        else:
            with open(__filepath, 'w', newline='', encoding='utf-8-sig') as o:
                csv_writer = csv.DictWriter(o, fieldnames=__fieldnames)
                csv_writer.writeheader()
                csv_writer.writerows(__parser_data)
    __filepath = None

