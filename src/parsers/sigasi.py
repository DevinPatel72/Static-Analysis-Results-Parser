# sigasi.py

import os
import logging
import traceback
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.language_resolver import resolve_lang
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames, console

logger = logging.getLogger(__name__)

sigasi_cdata = {}

def path_preview(fpath):
    # Parse the input file
    try:
        with open(fpath, 'r', encoding='utf-8-sig') as r:
            data = json.load(r)
        for issue in data['issues']:
            preview = issue.get('resource', '')
            if len(preview) > 0:
                return preview
    except json.JSONDecodeError:
        return f"[ERROR] Invalid JSON format"
    except Exception as e:
        return f"[ERROR] {e}"
    
    # No data, return error message
    return f"[ERROR] No data found in \'{fpath}\'"

def parse(fpath, scanner, substr, prepend):
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Keep track of issue number and errors
    issue_num = 0
    total_issues = 0
    finding_count = 0
    err_count = 0
    
    # Parse the JSON
    try:
        with open(fpath, 'r', encoding='utf-8-sig') as r:
            data = json.load(r)
    except (FileNotFoundError, json.JSONDecodeError):
        logger.error(f"[ERROR] Invalid JSON format: {fpath}")
        return finding_count, err_count + 1
    
    issues = data['issues']
    
    # Get total number of findings
    total_issues = len(issues)
    
    for issue in issues:
        issue_num += 1
        try:
            progress_bar(issue_num, total_issues, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
        
            # Get path/line and resolve language
            path = issue['resource']
            line = issue['line']
            line = int(line) if str(line).isdigit() else line
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = path.replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            # Resolve language of the file
            lang = resolve_lang(os.path.splitext(path)[1])
            
            description = issue['description']
            severity = issue['severity']
            
            # Get issue code for CWE mapping
            issue_code = issue['code']
            issue_code_description = issue.get('codeDescription', issue_code)
            issue_code_number = str(issue_code.split('.')[-1])
            
            # Map CWE
            if 'vhdl' in issue_code.lower():
                cwe = get_sigasi_cdata(issue_code_number, 'vhdl', default='')
            elif 'verilog' in issue_code.lower():
                cwe = get_sigasi_cdata(issue_code_number, 'verilog', default='')
            # Custom overrides
            elif 'Could not find declaration' in description:
                cwe = '457'
            else:
                logger.warning(f"Code \"{issue_code}\" not defined in sigasi_cdata.json")
                err_count += 1
                cwe = ''
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            preimage = '\0'.join(str(p) for p in (path, line, issue_code, description) if len(str(p)) > 0)
            id = idgenerator.hash(preimage)

            # Write row to outfile
            parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                                Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                                Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                                Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                                Fieldnames.PROPOSED_MITIGATION.value:'',
                                Fieldnames.VALIDATOR_COMMENT.value:'',
                                Fieldnames.ID.value:id,
                                Fieldnames.TYPE.value:issue_code_description,
                                Fieldnames.PATH.value:path,
                                Fieldnames.LINE.value:line,
                                Fieldnames.SYMBOL.value:'',
                                Fieldnames.MESSAGE.value:description,
                                Fieldnames.TRACE.value:'',
                                Fieldnames.TOOL_CWE.value:tool_cwe,
                                Fieldnames.TOOL.value:'',
                                Fieldnames.SCANNER.value:scanner,
                                Fieldnames.LANGUAGE.value:lang,
                                Fieldnames.SEVERITY.value:severity
                            })
            finding_count += 1
        except Exception:
            logger.error(f"Finding with issue number {issue_num} in \'{fpath}\': {traceback.format_exc()}")
            err_count += 1
    
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return finding_count, err_count
# End of parse

def load_sigasi_cdata():
    from . import PROG_NAME_ABBR, MAPPINGS_DIR
    
    try:
        with open(os.path.join(MAPPINGS_DIR, 'sigasi_cdata.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
    except (FileNotFoundError, json.JSONDecodeError):
        console(f"Unable to load Sigasi CWE mappings: Invalid JSON format\n{PROG_NAME_ABBR} will continue without CWE mappings.", "Config Error", type='error', orig_name=__name__)
        return {"__sigasi_cdata_error__": "Returning a dict of size 1 to ensure this function only gets called once."}

def get_sigasi_cdata(rule_id, rule_type, default=''):
    # Maps sigasi rule_id to CWE number and returns it
    global sigasi_cdata
    
    if rule_id == '__sigasi_cdata_error__':
        return default
    
    if len(sigasi_cdata) <= 0:
        sigasi_cdata = load_sigasi_cdata()
    
    if rule_type == 'vhdl':
        return sigasi_cdata['vhdl'].get(key=rule_id, default=default)
    elif rule_type == 'verilog':
        return sigasi_cdata['verilog'].get(key=rule_id, default=default)
    else:
        return default
