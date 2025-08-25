# fortify_csv.py

import os
import logging
import csv
import traceback
from . import FLAG_VULN_MAPPING
from .parser_tools import idgenerator, parser_writer
from .parser_tools.cwe_categories import cwe_categories
from .parser_tools.language_resolver import resolve_lang
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    try:
        with open(fpath, "r", encoding='utf-8-sig') as read_obj:
            # Determine deliminator character
            sep_line = read_obj.readline()
            
            if sep_line.startswith('sep='):
                delim = sep_line.strip().split('=')[1]
            else:
                read_obj.seek(0)
                delim = ','
            
            # Read first row of csv
            csv_reader = csv.DictReader(read_obj, delimiter=delim)
            first_row = next(csv_reader)
            cell_preview = first_row['path'].split(':')[0]
            return cell_preview
    except Exception:
        return f"[ERROR] {traceback.print_exc()}"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Keep track of row number and error count
    row_num = 0
    total_rows = 0
    finding_count = 0
    err_count = 0
    
    # Get total number of findings
    with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
        sep_line = read_obj.readline()
        
        if sep_line.startswith('sep='):
            delim = sep_line.strip().split('=')[1]
        else:
            read_obj.seek(0)
            delim = ','
        
        total_rows = len([row[list(row.keys())[0]] for row in csv.DictReader(read_obj, delimiter=delim)])
    
    
    # Open csv in read
    with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
        # Determine deliminator character
        sep_line = read_obj.readline()
        
        if sep_line.startswith('sep='):
            delim = sep_line.strip().split('=')[1]
        else:
            read_obj.seek(0)
            delim = ','
        
        csv_dict_reader = csv.DictReader(read_obj, delimiter=delim)
        
        # Loop through every row in CSV
        for row in csv_dict_reader:
            try:
                row_num += 1
                progress_bar(row_num, total_rows, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
                
                # Fortify CSVs do not output CWE. Keep this code in case a fortify cwe map is made in the future
                cwe = ''
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # Perform cwe overrides if user requests
                cwe, confidence = cwe_conf_override(control_flags, override_name=row['category'], cwe=cwe, override_scanner='fortify')
                
                # Check if cwe is in categories dict
                if control_flags[FLAG_VULN_MAPPING] and len(cwe) > 0 and cwe in cwe_categories.keys():
                    cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
                else:
                    cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
            
                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path, line = row['path'].split(':')
                path = path.replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                
                line = int(line) if str(line).isdigit() else line
                
                # Resolve language of the file
                lang = resolve_lang(os.path.splitext(path)[1])
                
                # Generate ID for Fortify finding (concat Path, Line, Scanner, Category, and Analyzer)
                preimage = f"{path}{line}{row['category']}"
                id = idgenerator.hash(preimage)
                #id = "FORT{:04}".format(finding_count+1)

                # Write row to outfile
                parser_writer.write_row({'CWE':cwe_cat,
                                    'Confidence':confidence,
                                    'Maturity':'Proof of Concept',
                                    'Mitigation':'None',
                                    'Mitigation Comment':'',
                                    'Comment':'',
                                    'ID':id,
                                    'Type': row['category'],
                                    'Path':path,
                                    'Line':line,
                                    'Symbol':'',
                                    'Message':'',
                                    'Tool CWE':tool_cwe,
                                    'Tool':row['analyzer'],
                                    'Scanner':scanner,
                                    'Language':lang,
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