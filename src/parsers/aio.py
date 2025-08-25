# aio.py
import os
import logging
import traceback
import csv
from .parser_tools import parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override

__excel_enabled = False

try:
    import openpyxl
    __excel_enabled = True
except ImportError:
    __excel_enabled = False

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    try:
        if __excel_enabled:
            workbook = openpyxl.load_workbook(fpath)
            sheet = workbook[workbook.sheetnames[0]]
            
            # Extract Path header
            path_col = None
            for cell in sheet[1]:
                if cell.value == 'Path':
                    path_col = cell.column
            
            if path_col is None:
                raise ValueError("No \'Path\' column found")

            cell_preview = sheet.cell(row=2, column=path_col).value
            return cell_preview
        else:
            with open(fpath, "r", encoding='utf-8-sig') as read_obj:
                csv_reader = csv.DictReader(read_obj)
                first_row = next(csv_reader)
                cell_preview = first_row['Path']
                return cell_preview
    except Exception as e:
        return f"[ERROR] {e}"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Keep track of row number and errors
    data = None
    row_num = 0
    total_rows = 0
    finding_count = 0
    err_count = 0
    
    # Excel - Set data iterable and total_rows
    if __excel_enabled and fpath.endswith('.xlsx'):
        workbook = openpyxl.load_workbook(fpath)
        sheet = workbook[workbook.sheetnames[0]]
        headers = [cell.value for cell in sheet[1]]
        
        # Extract rows as dictionaries
        data = []
        for row in sheet.iter_rows(min_row=2, values_only=True):
            row_data = {headers[col_idx]: row[col_idx] for col_idx in range(len(headers))}
            data.append(row_data)
        total_rows = len(data)
        
    # CSV - Set data iterable and total_rows
    else:
        # Get total number of findings
        with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
            total_rows = len([row[list(row.keys())[0]] for row in csv.DictReader(read_obj)])
        
        # Open csv in read
        with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
            data = csv.DictReader(read_obj)
            
    # Loop through every row in input file
    for row in data:
        try:
            row_num += 1
            progress_bar(row_num, total_rows, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))

            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = str(row['Path']).replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            # Perform cwe overrides if user requests
            cwe, confidence = cwe_conf_override(control_flags, override_name=row['Type'], cwe=row['CWE'], override_scanner=current_parser)
            
            new_row = {k:v for k,v in row.items()}
            new_row['Path'] = path
            new_row['CWE'] = cwe
            new_row['Confidence'] = confidence
            
            # Write row to outfile
            parser_writer.write_row(new_row)
            finding_count += 1
        except Exception:
            logger.error(f"Row {row_num} of \'{fpath}\': {traceback.format_exc()}")
            err_count += 1
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse
