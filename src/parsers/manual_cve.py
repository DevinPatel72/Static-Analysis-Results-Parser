# manual_cve.py

import os
import re
import logging
import csv
import traceback
from .parser_tools import idgenerator, parser_writer
from .parser_tools.user_overrides import cwe_conf_override
from .parser_tools.progressbar import SPACE,progress_bar

logger = logging.getLogger(__name__)

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
                
                # Extract CWE
                cwe = row['CWE']
                
                # Extract CVE
                cve = row['CVE']
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # Perform cwe overrides if user requests
                cve, confidence = cwe_conf_override(control_flags, override_name=cve, cwe=cve, message_content=row['Vulnerability'], override_scanner=current_parser)
                if confidence == 'To Verify': confidence = 'Confirmed'
                
                # Generate ID for Fortify finding (concat CVE, CWE, Path, Scanner, and Vulnerability)
                preimage = f"{cve}{tool_cwe}MANUAL{row['Vulnerability']}"
                id = idgenerator.hash(preimage)
                #id = "MAN{:04}".format(finding_count+1)
                
                # Quick check to ensure CVE is actually a CVE
                if not (re.match(r'^CVE-\d{4}-\d+$', cve)):
                    err_count += 1
                    logger.error(f"Row {row_num} of \'{fpath}\': Invalid CVE number. Please check \'{fpath}\' and the user overrides.")

                # Write row to outfile
                parser_writer.write_row({'CWE':cve,
                                    'Confidence':'Confirmed',
                                    'Maturity':'High',
                                    'Mitigation':'None',
                                    'Mitigation Comment':'',
                                    'Comment':'[{}]'.format(cve),
                                    'ID':id,
                                    'Type': '',
                                    'Path':'',
                                    'Line':'',
                                    'Symbol':row['DependencyName'],
                                    'Message':row['Vulnerability'],
                                    'Tool CWE':tool_cwe,
                                    'Tool':'',
                                    'Scanner':'MANUAL',
                                    'Language':'',
                                    'Severity': row['Severity']
                                })
                finding_count += 1
            except Exception:
                logger.error(f"Row {row_num} of \'{fpath}\': {traceback.format_exc()}")
                err_count += 1
    logger.info(f"Successfully processed {finding_count} vulnerabilities")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse