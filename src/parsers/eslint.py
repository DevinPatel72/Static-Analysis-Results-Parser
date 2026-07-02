# eslint.py
import os
import logging
import traceback
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE, progress_bar
from .parser_tools.toolbox import Fieldnames, console

logger = logging.getLogger(__name__)

eslint_cdata = {}

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

def parse(fpath, scanner, substr, prepend):
    logger.info("Parsing %s - %s", scanner, fpath)
    
    # Count findings and errors encountered while running
    finding_count = 0
    err_count = 0

    # Open json in read
    try:
        with open(fpath, mode='r', encoding='utf-8-sig') as f:
            data = json.load(f)
    except:
        logger.error("File \'%s\' failed to open:\n%s", fpath, traceback.format_exc())
        return finding_count, err_count + 1
    
    # Keep track of issue number for debug
    issue_num = 0
    total_issues = 0
    
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
                    logger.warning("Skipping message %d because its ruleId is null.\n    Location: %s:%d\n    Message: %s", issue_num, file['filePath'], message['line'], message['message'])
                    continue
                
                # Map eslint message id to CWE
                cwe = get_eslint_cdata(rule_id, default='')
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
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
                preimage = '\0'.join(str(p) for p in (path, message['line'], rule_id, message['message']) if len(str(p)) > 0)
                id = idgenerator.hash(preimage)
                #id = "ESL{:04}".format(finding_count+1)

                # Write row to outfile
                parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                                    Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                                    Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                                    Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                                    Fieldnames.PROPOSED_MITIGATION.value:'',
                                    Fieldnames.VALIDATOR_COMMENT.value:'',
                                    Fieldnames.ID.value:id,
                                    Fieldnames.TYPE.value:rule_id,
                                    Fieldnames.PATH.value:path,
                                    Fieldnames.LINE.value:line,
                                    Fieldnames.SYMBOL.value:'',
                                    Fieldnames.MESSAGE.value:message['message'],
                                    Fieldnames.TRACE.value:'',
                                    Fieldnames.TOOL_CWE.value:tool_cwe,
                                    Fieldnames.TOOL.value:'',
                                    Fieldnames.SCANNER.value:scanner,
                                    Fieldnames.LANGUAGE.value:'javascript',
                                    Fieldnames.SEVERITY.value:severity
                                })
                finding_count += 1
            except:
                logger.error("Issue %d in file \'%s\' of json file \'%s\':\n%s", issue_num, file['filePath'], fpath, traceback.format_exc())
                err_count += 1
    logger.info("Successfully processed %d findings", finding_count)
    logger.info("Number of erroneous findings: %d", err_count)
    return finding_count, err_count
# End of parse

def load_eslint_cdata():
    # Loads eslint cdata info from config dir
    from . import PROG_NAME_ABBR, MAPPINGS_DIR
    
    try:
        with open(os.path.join(MAPPINGS_DIR, 'eslint_cdata.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
    except (FileNotFoundError, json.JSONDecodeError):
        console(f"Unable to load Eslint CWE mappings: Invalid JSON format\n{PROG_NAME_ABBR} will continue without CWE mappings.", "Config Error", type='error', orig_name=__name__)
        return {"__eslint_cdata_error__": "Returning a dict of size 1 to ensure this function only gets called once."}

def get_eslint_cdata(rule_id, default=''):
    # Maps eslint rule_id to CWE number and returns it
    global eslint_cdata
    
    if rule_id == '__eslint_cdata_error__':
        return default
    
    if len(eslint_cdata) <= 0:
        eslint_cdata = load_eslint_cdata()
    
    return eslint_cdata.get(key=rule_id, default=default)
