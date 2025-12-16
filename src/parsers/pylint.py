# pylint.py
import os
import logging
import traceback
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override
from .parser_tools.toolbox import Fieldnames, console

logger = logging.getLogger(__name__)

pylint_cdata = {}

def path_preview(fpath):
    # Open json in read
    try:
        with open(fpath, mode='r', encoding='utf-8-sig') as f:
            data = json.load(f)
            return data[0]['path']
    except json.JSONDecodeError:
        return "[ERROR] Invalid JSON format"
    except Exception as e:
        return f"[ERROR] {e}"

def parse(fpath, scanner, substr, prepend, control_flags):
    from . import FLAG_CATEGORY_MAPPING, cwe_categories
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
            if progress_bar(scanner, issue_num, total_issues, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE)):
                return err_count
            
            # Map pylint message id to CWE
            message_id = issue['message-id']
            cwe = get_pylint_cdata(message_id)
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Perform cwe overrides if user requests
            cwe, confidence = cwe_conf_override(control_flags, override_name=message_id, cwe=cwe, override_scanner=current_parser)
                
            # Check if cwe is in categories dict
            if control_flags[FLAG_CATEGORY_MAPPING] and len(cwe) > 0 and cwe in cwe_categories.keys():
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
            parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe_cat,
                                Fieldnames.CONFIDENCE.value:confidence,
                                Fieldnames.MATURITY.value:'Unreported',
                                Fieldnames.MITIGATION.value:'',
                                Fieldnames.PROPOSED_MITIGATION.value:'',
                                Fieldnames.VALIDATOR_COMMENT.value:'',
                                Fieldnames.ID.value:id,
                                Fieldnames.TYPE.value:issue['symbol'],
                                Fieldnames.PATH.value:path,
                                Fieldnames.LINE.value:line,
                                Fieldnames.SYMBOL.value:'',
                                Fieldnames.MESSAGE.value:message,
                                Fieldnames.TOOL_CWE.value:tool_cwe,
                                Fieldnames.TOOL.value:'',
                                Fieldnames.SCANNER.value:scanner,
                                Fieldnames.LANGUAGE.value:'python',
                                Fieldnames.SEVERITY.value:issue['type']
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

def load_pylint_cdata():
    from . import CONFIG_DIR
    
    try:
        with open(os.path.join(CONFIG_DIR, 'pylint_cdata.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
    except json.JSONDecodeError:
        console("Unable to load Pylint CWE mappings: Invalid JSON format\nThe program will continue without CWE mappings.", "Config Error", type='error')
        return [0]
    

def get_pylint_cdata(message_id, default=''):
    # Maps pylint message_id to CWE number and returns it
    global pylint_cdata
    
    if len(pylint_cdata) <= 0:
        pylint_cdata = load_pylint_cdata()
    
    if message_id in pylint_cdata.keys():
        return pylint_cdata[message_id]
    elif message_id[0] == 'R':
        return '710'
    elif message_id[0] == 'C':
        return '1076'
    else: return default
