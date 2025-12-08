# eslint.py
import os
import logging
import traceback
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE, progress_bar
from .parser_tools.user_overrides import cwe_conf_override
from .parser_tools.toolbox import console

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Open json in read
    try:
        with open(fpath, mode='r', encoding='utf-8-sig') as f:
            data = json.load(f)
            return data[0]['filePath']
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
    total_issues = 0
    
    eslint_cdata = load_eslint_cdata()
    
    # Find total number of issues
    for file in data:
        total_issues += len(file['messages'])
    
    # Loop through every file in json
    for file in data:
        for message in file['messages']:
            try:
                issue_num += 1
                progress_bar(issue_num, total_issues, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
                
                rule_id = message['ruleId']
                
                if rule_id is None or rule_id == 'null':
                    logger.warning(f"Skipping message {issue_num} because its ruleId is null.\n    Location: {file['filePath']}:{message['line']}\n    Message: {message['message']}")
                    continue
                
                # Map eslint message id to CWE
                if rule_id in eslint_cdata.keys():
                    cwe = eslint_cdata[rule_id]
                else: cwe = ''
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # Perform cwe overrides if user requests
                cwe, confidence = cwe_conf_override(control_flags, override_name=rule_id, cwe=cwe, override_scanner=current_parser)
                    
                # Check if cwe is in categories dict
                if control_flags[FLAG_CATEGORY_MAPPING] and len(cwe) > 0 and cwe in cwe_categories.keys():
                    cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
                else:
                    cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                
                # Parse severity because it is a number
                if message['severity'] == 1:
                    severity = 'warning'
                elif message['severity'] == 2:
                    severity = 'error'
                elif message['severity'] == 0:
                    severity = 'off'
                else:
                    severity = ''
                

                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path = str(file['filePath']).replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                
                line = int(message['line']) if str(message['line']).isdigit() else message['line']
                
                # Generate ID for finding (concat Path, Line, RuleID, and Message)
                preimage = f"{path}{message['line']}{rule_id}{message['message']}"
                id = idgenerator.hash(preimage)
                #id = "ESL{:04}".format(finding_count+1)

                # Write row to outfile
                parser_writer.write_row({'Scoring Basis':cwe_cat,
                                    'Confidence':confidence,
                                    'Exploit Maturity':'Unreported',
                                    'Mitigation CVSS Vector':'',
                                    'Proposed Mitigation':'',
                                    'Validator Comment':'',
                                    'ID':id,
                                    'Type':rule_id,
                                    'Path':path,
                                    'Line':line,
                                    'Symbol':'',
                                    'Message':message['message'],
                                    'Tool CWE':tool_cwe,
                                    'Tool':'',
                                    'Scanner':scanner,
                                    'Language':'javascript',
                                    'Tool Severity':severity
                                })
                finding_count += 1
            except:
                logger.error("Issue {} in file \'{}\' of json file \'{}\':\n{}".format(issue_num, file['filePath'], fpath, traceback.format_exc()))
                err_count += 1
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous findings: {err_count}")
    return err_count
# End of parse

def load_eslint_cdata():
    from . import CONFIG_DIR
    
    try:
        with open(os.path.join(CONFIG_DIR, 'eslint_cdata.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
    except json.JSONDecodeError:
        console("Unable to load Eslint CWE mappings: Invalid JSON format\nThe program will continue without CWE mappings.", "Config Error", type='error')
        return [0]
