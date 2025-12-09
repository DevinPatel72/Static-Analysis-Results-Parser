# sigasi.py

import os
import logging
import traceback
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.language_resolver import resolve_lang
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override
from .parser_tools.toolbox import Fieldnames, console

logger = logging.getLogger(__name__)

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

def parse(fpath, scanner, substr, prepend, control_flags):
    from . import FLAG_CATEGORY_MAPPING, cwe_categories
    current_parser = __name__.split('.')[1]
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
    except json.JSONDecodeError:
        logger.error(f"[ERROR] Invalid JSON format: {fpath}")
        return err_count + 1
    
    sigasi_cdata = load_sigasi_cdata()
    
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
                cwe = sigasi_cdata['vhdl'].get(issue_code_number, '')
            elif 'verilog' in issue_code.lower():
                cwe = sigasi_cdata['verilog'].get(issue_code_number, '')
            
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
            
            # Perform cwe overrides if user requests
            cwe, confidence = cwe_conf_override(control_flags, override_name=issue_code, cwe=cwe, override_scanner=current_parser)
            
            # Check if cwe is in categories dict
            if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
            else:
                cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
            
            preimage = f"{path}{line}{issue_code}{description}"
            id = idgenerator.hash(preimage)

            # Write row to outfile
            parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe_cat,
                                Fieldnames.CONFIDENCE.value:confidence,
                                Fieldnames.MATURITY.value:'Unreported',
                                Fieldnames.MITIGATION.value:'',
                                Fieldnames.PROPOSED_MITIGATION.value:'',
                                Fieldnames.VALIDATOR_COMMENT.value:'',
                                Fieldnames.ID.value:id,
                                Fieldnames.TYPE.value:issue_code_description,
                                Fieldnames.PATH.value:path,
                                Fieldnames.LINE.value:line,
                                Fieldnames.SYMBOL.value:'',
                                Fieldnames.MESSAGE.value:description,
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
    return err_count
# End of parse

def load_sigasi_cdata():
    from . import CONFIG_DIR
    
    try:
        with open(os.path.join(CONFIG_DIR, 'sigasi_cdata.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
    except json.JSONDecodeError:
        console("Unable to load Sigasi CWE mappings: Invalid JSON format\nThe program will continue without CWE mappings.", "Config Error", type='error')
        return [0]
