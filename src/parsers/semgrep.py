# semgrep.py

import os
import logging
import traceback
import re
import csv
import json
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
        with open(fpath, 'r', encoding='utf-8-sig') as r:
            if fpath.endswith('.json'):
                data = json.load(r)
            elif fpath.endswith('.csv'):
                reader = csv.DictReader(r)
                data = {'findings': [row for row in reader]}
            else:
                return "[ERROR] Unsupported file type for Semgrep"
        for finding in data['findings']:
            preview = finding.get('path','')
            if len(preview) > 0:
                return preview
    except json.JSONDecodeError:
        return "[ERROR] Invalid JSON format"
    except Exception as e:
        return f"[ERROR] {e}"
    
    # No data, return error message
    return f"[ERROR] No data found in \'{fpath}\'"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Keep track of finding number and errors
    finding_num = 0
    total_findings = 0
    finding_count = 0
    err_count = 0
    
    # Check input file type. Both CSVs and JSONs are parsed as dictionary types, so no new functions are necessary.
    try:
        with open(fpath, 'r', encoding='utf-8-sig') as r:
            if fpath.endswith('.json'):
                data = json.load(r)
            elif fpath.endswith('.csv'):
                reader = csv.DictReader(r)
                data = {'findings': [row for row in reader]}
            else:
                logger.error(f"Unsupported file type for semgrep results: {fpath}")
                return err_count + 1
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON format: {fpath}")
        return err_count + 1
    except Exception:
        logger.error(f"Unable to read file: {fpath}")
        return err_count + 1
    
    # Get meta information
    scanner_version = data.get('semgrep_version', '')
    if len(scanner_version) > 0:
        scanner = f"Semgrep {scanner_version}"
    
    findings = data['findings']
    
    # Get total number of findings
    total_findings = len(findings)
    
    for finding in findings:
        finding_num += 1
        try:
            progress_bar(finding_num, total_findings, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
        
            # Get path/line and resolve language
            path = finding['path']
            line = finding['start_line']
            line = int(line) if str(line).isdigit() else line
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = path.replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            # Resolve language of the file
            lang = resolve_lang(os.path.splitext(path)[1])
            
            # Get CWE
            cwe = finding.get('cwe', [])
            if len(cwe) <= 0:
                cwe = ''
            else:
                cwe = cwe[0]
                if (m := re.search(r"CWE-(\d+):.*", cwe)):
                    cwe = m.group(1)
                else:
                    logger.warning(f'Failed to parse CWE for {fpath}, bad regex matching.') # @DEBUG
                    cwe = ''
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Get check_id for Type
            check_id = finding['check_id']
            
            # Perform cwe overrides if user requests
            cwe, confidence = cwe_conf_override(control_flags, override_name=check_id, cwe=cwe, override_scanner=current_parser)
            
            # Check if cwe is in categories dict
            if control_flags[FLAG_VULN_MAPPING] and cwe in cwe_categories.keys():
                cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
            else:
                cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                
            message = finding['message']
            severity = finding['severity']
            
            # Get end line as a trace if it is different than start line
            if int(finding['start_line']) != int(finding['end_line']):
                message += f"\nTrace:\n<Start> {path}:{finding['start_line']}\n<End> {path}:{finding['end_line']}"
            
            preimage = f"{path}{line}{check_id}{message}"
            id = idgenerator.hash(preimage)

            # Write row to outfile
            parser_writer.write_row({'CWE':cwe_cat,
                                'Confidence':confidence,
                                'Maturity':'Proof of Concept',
                                'Mitigation':'None',
                                'Mitigation Comment':'',
                                'Comment':'',
                                'ID':id,
                                'Type':check_id,
                                'Path':path,
                                'Line':line,
                                'Symbol':'',
                                'Message':message,
                                'Tool CWE':tool_cwe,
                                'Tool':'',
                                'Scanner':scanner,
                                'Language':lang,
                                'Severity':severity
                            })
            finding_count += 1
        except Exception:
            logger.error(f"Finding with finding number {finding_num} in \'{fpath}\': {traceback.format_exc()}")
            err_count += 1
    
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse
