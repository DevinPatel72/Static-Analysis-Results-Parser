# checkmarx_csv.py
import os
import logging
import traceback
import csv
from . import FLAG_VULN_MAPPING
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override
from .parser_tools.cwe_categories import cwe_categories
from .parser_tools.cdata import cdata as CWEList

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    for file in os.listdir(fpath):
        try:
            with open(os.path.join(fpath, file), "r", encoding='utf-8-sig') as read_obj:
                csv_reader = csv.DictReader(read_obj)
                first_row = next(csv_reader)
                cell_preview = first_row['SrcFileName']
                return cell_preview # Immediately return valid value
        
        except StopIteration:
            continue # Wait until all files are iterated through before returning this
        
        except Exception as e:
            return f"[ERROR] {e}" # Immediately return unknown exception message
    # No data, return error message
    return "[ERROR] No data found in CSV files"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Count errors encountered while running
    err_count = 0
        
    # Keep track of row number for progressbar
    i = 0
    finding_count = 0
    
    total_findings = _get_total(fpath)
    
    # Loop through directory
    for filename in os.listdir(fpath):
        # Check if the file is a csv
        if os.path.splitext(filename)[1] != '.csv':
            logger.info(f"Skipping \"{filename}\", not a csv file")
            continue
        
        # Create full path with directory and filename
        f = os.path.join(fpath, filename)
        
        # Open csv in read
        with open(f, mode='r', encoding='utf-8-sig') as read_obj:
            csv_dict_reader = csv.DictReader(read_obj)
            
            # Keep track of row number for debug
            row_num = 0
            
            # Loop through every row in CSV
            for row in csv_dict_reader:
                try:
                    row_num += 1
                    i+=1
                    progress_bar(i, total_findings, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
            
                    # row variable is a dictionary that represents a row in csv
                    lang = row['QueryPath'].split('\\')[0]

                    # Check CWEList in cdata.py
                    test = list((c for c in CWEList if 
                                c['Lang'] == lang 
                                and c['Query'] == row['Query'].replace(' ','_')))
                    
                    if lang == 'CPP': lang = 'c/c++'
                    else: lang = lang.lower()

                    # Set CWE # if found, else leave it blank.
                    cwe = test[0]['CWE'] if len(test) > 0 else ''
                    
                    # Get tool cwe before any overrides are performed
                    if len(cwe) <= 0:
                        tool_cwe = '(blank)'
                    else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                    
                    query = row['Query']
                    
                    # Perform cwe overrides if user requests
                    cwe, confidence = cwe_conf_override(control_flags, override_name=query, cwe=cwe, override_scanner=current_parser)
                    
                    # Check if cwe is in categories dict
                    if control_flags[FLAG_VULN_MAPPING] and cwe in cwe_categories.keys():
                        cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
                    else:
                        cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                    
                    # Cut and prepend the paths and convert all backslashes to forwardslashes
                    path = str(row['SrcFileName']).replace(substr, "", 1)
                    path = os.path.join(prepend, path).replace('\\', '/')
                    dest_path = str(row['DestFileName']).replace(substr, "", 1)
                    dest_path = os.path.join(prepend, path).replace('\\', '/')
                    
                    line = int(row['Line']) if str(row['Line']).isdigit() else row['Line']
                    dest_line = int(row['DestLine']) if str(row['DestLine']).isdigit() else row['DestLine']
                    
                    # Put Dest info in the message column
                    #dest_info = f"Destination: {row['DestFileName']}:{row['DestLine']}: \"{row['DestName']}\""
                
                    # Generate ID for finding
                    preimage = f"{path}{row['Line']}{row['Name']}{query}{tool_cwe}{dest_path}{row['DestLine']}{row['DestName']}"
                    id = idgenerator.hash(preimage)
                    #id = "CX{:04}".format(finding_count+1)
                    
                    # Write row to outfile
                    parser_writer.write_row({'CWE':cwe_cat,
                                         'Confidence':confidence,
                                         'Maturity':'Proof of Concept',
                                         'Mitigation':'None',
                                         'Mitigation Comment':'',
                                         'Comment':'',
                                         'ID':id,
                                         'Type':query,
                                         'Path':path,
                                         'Line':line,
                                         'Symbol':row['Name'],
                                         'Message':'',
                                         'DestPath':dest_path,
                                         'DestLine':dest_line,
                                         'DestSymbol':row['DestName'],
                                         'Tool CWE': tool_cwe,
                                         'Tool':'',
                                         'Scanner':scanner,
                                         'Language':lang,
                                         'Severity':row['Result Severity']
                                        })
        
                    finding_count += 1
                except Exception:
                    logger.error(f"Row {row_num} of \'{fpath}\': {traceback.format_exc()}")
                    err_count += 1
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse

def _get_total(path):
    finding_count = 0
    
    for filename in os.listdir(path):
        if not filename.endswith('.csv'):
            continue
        f = os.path.join(path, filename)
        with open(f, mode='r', encoding='utf-8-sig') as read_obj:
            finding_count += len([row[list(row.keys())[0]] for row in csv.DictReader(read_obj)])
            
    return finding_count
# End of _get_total
