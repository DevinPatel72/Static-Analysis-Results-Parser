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

__fp = None
__parser_writer = None
__excel_workbook = None
__fieldnames = None

def open_writer(outfile, fieldnames, sheet_name='Sheet1', force_csv=False):
    global __fp, __parser_writer, __excel_workbook, __fieldnames, __excel_enabled
    from parsers import GUI_MODE
    
    __fieldnames = fieldnames
    
    while True:
        try:
            # Update the boolean to include whether the user requests CSV
            __excel_enabled = __excel_enabled and not force_csv
            if __excel_enabled:
                if os.path.splitext(outfile)[1] != '.xlsx':
                    outfile = os.path.splitext(outfile)[0] + '.xlsx'
                __fp = outfile
                __excel_workbook = openpyxl.Workbook()
                __parser_writer = __excel_workbook.active
                __parser_writer.title = sheet_name
                __parser_writer.append([header for header in __fieldnames])
            else:
                if os.path.splitext(outfile)[1] != '.csv':
                    outfile = os.path.splitext(outfile)[0] + '.csv'
                __fp = open(outfile, 'w', newline='', encoding='utf-8-sig')
                __parser_writer = csv.DictWriter(__fp, fieldnames=fieldnames)
                __parser_writer.writeheader()
            break
        except PermissionError:
            if GUI_MODE:
                from tkinter import messagebox
                messagebox.showerror("Unable to open file", f"File \"{outfile}\" cannot be opened.\n\nTo continue, please make sure the file is not already open in another program.\n\nPress Enter to continue...")
            else:
                print(f"File \"{outfile}\" cannot be opened. To continue, please make sure the file is not already open in another program.\nPress Enter to continue...")
            
def write_row(r):
    if __excel_enabled:
        __parser_writer.append([r.get(header, '') for header in __fieldnames])
    else:
        __parser_writer.writerow(r)

@atexit.register
def close_writer():
    global __fp
    if __fp is not None:
        from parsers import GUI_MODE
        if __excel_enabled:
            while True:
                try:
                    __excel_workbook.save(__fp)
                    break
                except PermissionError:
                    if GUI_MODE:
                        from tkinter import messagebox
                        messagebox.showerror("Unable to open file", f"File \"{__fp}\" cannot be opened.\n\nTo continue, please make sure the file is not already open in another program.\n\nPress Enter to continue...")
                    else:
                        print(f"File \"{__fp}\" cannot be opened. To continue, please make sure the file is not already open in another program.\nPress Enter to continue...")
        else:
            if not __fp.closed:
                __fp.close()
    __fp = None
