# pylint.py
import os
import logging
import traceback
import json
from . import FLAG_VULN_MAPPING
from .parser_tools import idgenerator, parser_writer
from .parser_tools.pylint_cdata import pylint_cdata
from .parser_tools.cwe_categories import cwe_categories
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Open json in read
    try:
        with open(fpath, mode='r', encoding='utf-8-sig') as f:
            data = json.load(f)
            return data[0]['path']
    except Exception as e:
        return f"[ERROR] {e}"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Count errors encountered while running
    err_count = 0

    # Open json in read
    try:
        with open(fpath, mode='r', encoding='utf-8-sig') as f:
            data = json.load(f)
    except:
        logger.error(f"File \'{fpath}\' failed to open:\n{traceback.format_exc()}")
        return err_count + 1
    
    # Keep track of issue number for debug
    issue_num = 0
    finding_count = 0
    total_issues = len(data)
    
    # Loop through every issue in json
    for issue in data:
        try:
            issue_num += 1
            progress_bar(issue_num, total_issues, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
            
            # Map pylint message id to CWE
            message_id = issue['message-id']
            if message_id in pylint_cdata.keys():
                cwe = pylint_cdata[message_id]
            elif message_id[0] == 'R':
                cwe = '710'
            elif message_id[0] == 'C':
                cwe = '1076'
            else: cwe = ''
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Perform cwe overrides if user requests
            cwe, confidence = cwe_conf_override(control_flags, override_name=message_id, cwe=cwe, override_scanner=current_parser)
                
            # Check if cwe is in categories dict
            if control_flags[FLAG_VULN_MAPPING] and len(cwe) > 0 and cwe in cwe_categories.keys():
                cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
            else:
                cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
            
            # Symbol duplicate-code prints entire source into the message, which is bad. Add a length limit
            if issue['symbol'] == 'duplicate-code':
                message = issue['message'][:100]
            else:
                message = issue['message']
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = str(issue['path']).replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            line = int(issue['line']) if str(issue['line']).isdigit() else issue['line']
            
            # Generate ID for finding (concat Path, Line, Scanner, and Message)
            preimage = f"{path}{issue['line']}{message}"
            id = idgenerator.hash(preimage)
            #id = "PYL{:04}".format(finding_count+1)

            # Write row to outfile
            parser_writer.write_row({'CWE':cwe_cat,
                                'Confidence':confidence,
                                'Maturity':'Proof of Concept',
                                'Mitigation':'None',
                                'Mitigation Comment':'',
                                'Comment':'',
                                'ID':id,
                                'Type':issue['symbol'],
                                'Path':path,
                                'Line':line,
                                'Symbol':'',
                                'Message':message,
                                'Tool CWE':tool_cwe,
                                'Tool':'',
                                'Scanner':scanner,
                                'Language':'python',
                                'Severity':issue['type']
                            })
            finding_count += 1
        except:
            logger.error(f"Issue {issue_num} of \'{fpath}\':\n{traceback.format_exc()}")
            err_count += 1
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous findings: {err_count}")
    return err_count
# End of parse

# Pylint message IDs that are not related to the source
__INTERNAL_MESSAGES = ["F0002", "F0011", "F0001", "F0202", "F0010"]
