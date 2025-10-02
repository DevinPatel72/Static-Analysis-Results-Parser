# pragmatic.py
import os
import logging
import traceback
import csv
from . import FLAG_CATEGORY_MAPPING, cwe_categories
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    try:
        with open(fpath, "r", encoding='utf-8-sig') as read_obj:
            csv_reader = csv.DictReader(read_obj)
            first_row = next(csv_reader)
            cell_preview = first_row['Filename']
            return cell_preview
    except Exception as e:
        return f"[ERROR] {e}"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Keep track of row number and errors
    row_num = 0
    total_rows = 0
    finding_count = 0
    err_count = 0
    
    # Get total number of findings
    with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
        total_rows = len([row[list(row.keys())[0]] for row in csv.DictReader(read_obj)])
    
    # Open csv in read
    with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
        csv_dict_reader = csv.DictReader(read_obj)
        
        # Loop through every row in CSV
        for row in csv_dict_reader:
            try:
                row_num += 1
                progress_bar(row_num, total_rows, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
            
                cwe = row['CWE']
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # Perform cwe overrides if user requests
                cwe, confidence = cwe_conf_override(control_flags, override_name=row['Checker'], cwe=cwe, override_scanner=current_parser)
                
                # Check if cwe is in categories dict
                if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                    cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
                else:
                    cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                
                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path = str(row['Filename']).replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                
                line = int(row['Line']) if str(row['Line']).isdigit() else row['Line']
                
                # Generate ID for Coverity finding (concat Path, Line, Scanner, and Message)
                preimage = f"{path}{row['Line']}{row['Comments']}{tool_cwe}"
                id = idgenerator.hash(preimage)
                #id = "PRG{:04}".format(finding_count+1)

                # Write row to outfile
                parser_writer.write_row({'CWE':cwe_cat,
                                    'Confidence':confidence,
                                    'Maturity':'Proof of Concept',
                                    'Mitigation':'None',
                                    'Mitigation Comment':'',
                                    'Comment':'',
                                    'ID':id,
                                    'Type':row['Checker'],
                                    'Path':path,
                                    'Line':line,
                                    'Symbol':'',
                                    'Message':row['Comments'],
                                    'Tool CWE':tool_cwe,
                                    'Tool':'',
                                    'Scanner':row['Tool'],
                                    'Language':'ada',
                                    'Severity':''
                                })
                finding_count += 1
            except Exception:
                logger.error(f"Row {row_num} of \'{fpath}\': {traceback.format_exc()}")
                err_count += 1
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse
