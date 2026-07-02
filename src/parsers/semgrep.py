# semgrep.py

import os
import logging
import traceback
import re
import csv
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.language_resolver import resolve_lang
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames

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

def parse(fpath, scanner, substr, prepend):
    logger.info("Parsing %s - %s", scanner, fpath)
    
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
                logger.error("Unsupported file type for semgrep results: %s", fpath)
                return finding_count, err_count + 1
    except json.JSONDecodeError:
        logger.error("Invalid JSON format: %s", fpath)
        return finding_count, err_count + 1
    except Exception:
        logger.error("Unable to read file: %s", fpath)
        return finding_count, err_count + 1
    
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
                    logger.warning('Failed to parse CWE for %s, bad regex match.', fpath)
                    err_count += 1
                    cwe = ''
            
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Get check_id for Type
            check_id = finding['check_id']
                
            message = finding['message']
            severity = finding['severity']
            
            # Get end line as a trace if it is different than start line
            if int(finding['start_line']) != int(finding['end_line']):
                trace = f"1) {path}:{finding['start_line']}\n2) {path}:{finding['end_line']}"
            else:
                trace = ''
            
            preimage = '\0'.join(str(p) for p in (path, line, check_id, message, trace) if len(str(p)) > 0)
            id = idgenerator.hash(preimage)

            # Write row to outfile
            parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                                Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                                Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                                Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                                Fieldnames.PROPOSED_MITIGATION.value:'',
                                Fieldnames.VALIDATOR_COMMENT.value:'',
                                Fieldnames.ID.value:id,
                                Fieldnames.TYPE.value:check_id,
                                Fieldnames.PATH.value:path,
                                Fieldnames.LINE.value:line,
                                Fieldnames.SYMBOL.value:'',
                                Fieldnames.MESSAGE.value:message,
                                Fieldnames.TRACE.value:trace,
                                Fieldnames.TOOL_CWE.value:tool_cwe,
                                Fieldnames.TOOL.value:'',
                                Fieldnames.SCANNER.value:scanner,
                                Fieldnames.LANGUAGE.value:lang,
                                Fieldnames.SEVERITY.value:severity
                            })
            finding_count += 1
        except Exception:
            logger.error("Finding with finding number %d in \'%s\': %s", finding_num, fpath, traceback.format_exc())
            err_count += 1
    
    logger.info("Successfully processed %d findings", finding_count)
    logger.info("Number of erroneous rows: %d", err_count)
    return finding_count, err_count
# End of parse
