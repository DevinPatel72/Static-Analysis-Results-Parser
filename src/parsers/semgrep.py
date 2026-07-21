# semgrep.py

import os
import logging
import traceback
import re
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.language_resolver import resolve_lang_from_ext
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames, Scanners

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    try:
        with open(fpath, 'r', encoding='utf-8-sig') as r:
            data = json.load(r)
            if fpath.endswith('.json'):
                results = data['results']
            elif fpath.endswith('.sarif'):
                results = data['runs'][0]['results']
            else:
                return "[ERROR] Unsupported file type for Semgrep"
        for result in results:
            # Json
            if fpath.endswith('.json'):
                preview = result.get('path','')
            # SARIF
            else:
                try:
                    preview = result['locations'][0]['physicalLocation']['artifactLocation'].get('uri', '')
                except KeyError:
                    pass
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
    finding_count = 0
    err_count = 0
    
    data = []
    
    # Load data
    try:
        with open(fpath, 'r', encoding='utf-8-sig') as r:
            if fpath.endswith(Scanners.SEMGREP.valid_ext):
                data = json.load(r)
            else:
                logger.error("Unsupported file type for semgrep results: %s", fpath)
                return finding_count, err_count + 1
    except json.JSONDecodeError:
        logger.error("Invalid JSON format: %s", fpath)
        return finding_count, err_count + 1
    except Exception:
        logger.error("Unable to read file: %s", fpath)
        return finding_count, err_count + 1
    
    # Parse
    if fpath.endswith('.json'):
        finding_count, err_count = _parse_json(data, fpath, scanner, substr, prepend)
    else:
        finding_count, err_count = _parse_sarif(data, fpath, scanner, substr, prepend)
    
    logger.info("Successfully processed %d results", finding_count)
    logger.info("Number of erroneous results: %d", err_count)
    return finding_count, err_count


def _parse_sarif(data, fpath, scanner, substr, prepend):
    
    # Keep track of finding number and errors
    finding_count = 0
    err_count = 0
    result_num = 0
    total_results = 0
    
    # Get meta information
    scanner_name = data['runs'][0]['tool']['driver']['name']
    scanner_version = data['runs'][0]['tool']['driver']['semanticVersion']
    if len(scanner_version) > 0:
        scanner = f"{scanner_name} {scanner_version}"
    
    results = data['runs'][0]['results']
    
    # Get total number of results
    total_results = len(results)
    
    # Create dict that maps rule ID to rule
    rules = {}
    for rule in data['runs'][0]['tool']['driver']['rules']:
        rules[rule['id']] = rule
    
    for result in results:
        result_num += 1
        try:
            progress_bar(result_num, total_results, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
        
            # Get rule_id
            rule_id = result['ruleId']
        
            # Get path/line
            path = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
            line = result['locations'][0]['physicalLocation']['region']['endLine']
            line = int(line) if str(line).isdigit() else line
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = path.replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            # Resolve language of the file
            lang = resolve_lang_from_ext(os.path.splitext(path)[1])
            
            # Get CWE
            cwe = ''
            try:
                rule_tags = rules[rule_id]['properties']['tags']
            except KeyError:
                rule_tags = []
            
            for tag in rule_tags:
                if (m := re.search(r"CWE-(\d+):.*", tag)) is not None:
                    cwe = m.group(1)
                    break
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            
            # Message
            try:
                message = result['message']['text']
            except KeyError:
                message = ''
            
            # Severity
            try:
                severity = rules[rule_id]['defaultConfiguration']['level']
            except KeyError:
                severity = ''
            
            # Symbol
            try:
                snippet = result['locations'][0]['physicalLocation']['region']['snippet']['text']
            except KeyError:
                snippet = ''
            
            symbol = ''
            for l in snippet.split('\n'):
                symbol += l.strip() + '\n'
            symbol = symbol.strip()
            
            # Build trace if start_line != end_line
            try:
                start_line = result['locations'][0]['physicalLocation']['region']['startLine']
                start_line = int(start_line) if str(start_line).isdigit() else start_line
            except KeyError:
                start_line = -1
            if start_line > 0 and start_line != line:
                trace = f"1) {path}:{start_line}\n2) {path}:{line}"
            else:
                trace = ''
            
            preimage = '\0'.join(str(p) for p in (path, line, rule_id, message, trace) if len(str(p)) > 0)
            id = idgenerator.hash(preimage)

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
                                Fieldnames.SYMBOL.value:symbol,
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
            logger.error("Result at ordinal position %d in \'%s\': %s", result_num, fpath, traceback.format_exc())
            err_count += 1

    return finding_count, err_count
# End of _parse_sarif


def _parse_json(data, fpath, scanner, substr, prepend):
    
    # Keep track of finding number and errors
    finding_count = 0
    err_count = 0
    result_num = 0
    total_results = 0
    
    # Get meta information
    scanner_version = data.get('version', '')
    if len(scanner_version) > 0:
        scanner = f"Semgrep {scanner_version}"
    
    results = data['results']
    
    # Get total number of results
    total_results = len(results)
    
    for result in results:
        result_num += 1
        try:
            progress_bar(result_num, total_results, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
        
            # Get path/line
            path = result['path']
            line = result['end']['line']
            line = int(line) if str(line).isdigit() else line
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = path.replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            extra = result['extra']
            metadata = extra['metadata']
            
            # Resolve language of the file
            lang = metadata.get('technology', '')
            if len(lang) <= 0:
                lang = resolve_lang_from_ext(os.path.splitext(path)[1])
            else:
                lang = lang[0]
            
            # Get CWE
            cwe = metadata.get('cwe', '')
            if len(cwe) > 0:
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
            check_id = result['check_id']
            
            # Message, Severity, Symbol
            message = extra.get('message', '')
            severity = extra.get('severity', '')
            symbol = ''
            fix = extra.get('fix', '')
            for l in fix.split('\n'):
                symbol += l.strip() + '\n'
            symbol = symbol.strip()
            
            # Build trace if start_line != end_line
            if int(result['start']['line']) != int(result['end']['line']):
                trace = f"1) {path}:{result['start']['line']}\n2) {path}:{result['end']['line']}"
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
                                Fieldnames.SYMBOL.value:symbol,
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
            logger.error("Result at ordinal position %d in \'%s\': %s", result_num, fpath, traceback.format_exc())
            err_count += 1
    
    return finding_count, err_count
# End of _parse_json
