# sigasi.py

import os
import logging
import traceback
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.toolbox import console
from .parser_tools.language_resolver import resolve_lang
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override

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
            
            # Map CWE @TODO
            sigasi_cdata = load_sigasi_cdata()
            cwe = ''
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Get issue code
            issue_code = issue['code']
            issue_code_description = issue.get('codeDescription', issue_code)
            
            # Perform cwe overrides if user requests
            cwe, confidence = cwe_conf_override(control_flags, override_name=issue_code, cwe=cwe, override_scanner=current_parser)
            
            # Check if cwe is in categories dict
            if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
            else:
                cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                
            description = issue['description']
            severity = issue['severity']
            
            preimage = f"{path}{line}{issue_code}{description}"
            id = idgenerator.hash(preimage)

            # Write row to outfile
            parser_writer.write_row({'CWE':cwe_cat,
                                'Confidence':confidence,
                                'Maturity':'Proof of Concept',
                                'Mitigation':'None',
                                'Mitigation Comment':'',
                                'Comment':'',
                                'ID':id,
                                'Type':issue_code_description,
                                'Path':path,
                                'Line':line,
                                'Symbol':'',
                                'Message':description,
                                'Tool CWE':tool_cwe,
                                'Tool':'',
                                'Scanner':scanner,
                                'Language':lang,
                                'Severity':severity
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
