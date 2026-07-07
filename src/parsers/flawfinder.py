# flawfinder.py

import os
import re
import csv
import json
import logging
import traceback
from urllib.parse import unquote
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames
from .parser_tools.language_resolver import resolve_lang_from_ext

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    try:
        if fpath.endswith('.csv'):
            with open(fpath, "r", encoding='utf-8-sig') as read_obj:
                csv_reader = csv.DictReader(read_obj)
                first_row = next(csv_reader)
                cell_preview = first_row['File']
                return cell_preview
        else:
            with open(fpath, "r", encoding='utf-8-sig') as read_obj:
                data = json.load(read_obj)
                # Keep going until valid path is found
                for r in data['runs'][0]['results']:
                    try:
                        return _normalize_text(r['locations'][0]['physicalLocation']['artifactLocation']['uri'])
                    except KeyError:
                        continue
                return "[ERROR] No paths found in input file."
    except json.JSONDecodeError:
        return "[ERROR] Improperly formatted input file. Ensure Spotbugs is configured to output in SARIF format."
    except Exception as e:
        return f"[ERROR] {e}"

def parse(fpath, scanner, substr, prepend):
    logger.info("Parsing %s - %s", scanner, fpath)
    
    if fpath.endswith('.csv'):
        finding_count, err_count = _parse_csv(fpath, scanner, substr, prepend)
    else:
        finding_count, err_count = _parse_sarif(fpath, scanner, substr, prepend)
    
    logger.info("Successfully processed %d findings", finding_count)
    logger.info("Number of erroneous rows: %d", err_count)
    return finding_count, err_count

def _parse_sarif(fpath, scanner, substr, prepend):
    
    finding_count = 0
    result_num = 0
    
    # Count errors encountered while running
    err_count = 0
    
    # Load data
    try:
        with open(fpath, "r", encoding='utf-8-sig') as read_obj:
            data = json.load(read_obj)
    except (FileNotFoundError, json.JSONDecodeError):
        err_count += 1
        logger.error("Unable to parse input file \"%s\". Ensure %s is configured to output in SARIF format.", fpath, scanner)
        return finding_count, err_count
    
    # Get runs
    data = data['runs'][0]
    
    # Get total number of findings
    total_results = len(data['results'])
    
    # Get metadata
    scanner = "{} {}".format(data['tool']['driver']['name'], data['tool']['driver']['version'])
    
    # Get rules
    flawfinder_rules = {}
    for rule in data['tool']['driver']['rules']:
        rule_id = rule['id']
        name = rule['name']
        short_desc = _normalize_text(rule['shortDescription']['text'])
        
        append_cwe = {}
    
        for relationship in rule.get('relationships', []):
            if 'cwe' in relationship['target']['toolComponent']['name'].lower().strip():
                append_cwe['cweid'] = relationship['target'].get('id', '').replace('CWE-', '')
                break
        
        # Check if there is a "more-generic/more-specific" format of cwe in shortDescription
        if (m := re.search(r"\(CWE-\d+[!]?/CWE-(\d+)[!]?\)", short_desc)) is not None:
            append_cwe['cweid'] = m.group(1)
        
        flawfinder_rules[rule_id] = append_cwe | {"name": name, "shortDescription": short_desc}
    
    # Iterate through results
    for result in data['results']:
        try:
            result_num += 1
            progress_bar(result_num, total_results, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
        
            # Type
            rule_id = result['ruleId']
        
            # Get CWE and rule message
            rule = flawfinder_rules.get(rule_id, {})
            if len(rule) > 0:
                cwe = rule.get('cweid', '')
                finding_type = rule.get('name', '')
                message = rule.get('shortDescription', '')
            else:
                cwe = ''
                finding_type = ''
                message = ''
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else:
                tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = str(_normalize_text(result['locations'][0]['physicalLocation']['artifactLocation']['uri'])).replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            line = ''
            endline = ''
            
            try:
                line = str(result['locations'][0]['physicalLocation']['region']['startLine'])
                line = int(line) if line.isdigit() else line
                endline = str(result['locations'][0]['physicalLocation']['region'].get('endLine', line))
                endline = int(endline) if endline.isdigit() else endline
            except KeyError as ke:
                if 'region' in str(ke):
                    line = line if len(line) > 0 else ''
                    endline = line if len(endline) > 0 else ''
            
            # Language
            lang = resolve_lang_from_ext(os.path.splitext(path)[1])
            
            # Message from result
            message = result.get('message', {}).get('text', message)
            message = message.replace(finding_type+':', '')
            
            # Symbol
            try:
                region = result['locations'][0]['physicalLocation']['region']
                symbol = region.get('snippet', {}).get('text', '')
                symbol = symbol[:75] if len(symbol) > 75 else symbol
                symbol = symbol.strip()
            except KeyError as ke:
                if 'region' in str(ke):
                    symbol = ''
            
            # Severity
            severity = result['level']
            
            # Possible trace if startline != endline
            if line != endline:
                trace = f"1) {path}:{line}\n2) {path}:{endline}"
            else:
                trace = ""
            
            # Generate ID
            id = ''
            for k, v in result.get('fingerprints', {}).items():
                if 'contextHash' in k:
                    id = v
                    break
            if len(id) <= 0:
                preimage = '\0'.join(str(p) for p in (path, line, rule_id, message) if len(str(p)) > 0)
                id = idgenerator.hash(preimage)

            # Write row to outfile
            parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                                Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                                Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                                Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                                Fieldnames.PROPOSED_MITIGATION.value:'',
                                Fieldnames.VALIDATOR_COMMENT.value:'',
                                Fieldnames.ID.value:id,
                                Fieldnames.TYPE.value:finding_type,
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
            logger.error("Result with ID \"%s\", message %s in \'%s\': %s", rule_id, result.get('message', ''), fpath, traceback.format_exc())
            err_count += 1
        
    return finding_count, err_count
# End of _parse_sarif

def _parse_csv(fpath, scanner, substr, prepend):
    
    # Keep track of row number and errors
    row_num = 0
    total_rows = 0
    finding_count = 0
    err_count = 0
    
    # Get total number of findings
    with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
        total_rows = len([row[list(row.keys())[0]] for row in csv.DictReader(read_obj)])
    
    # Open csv in read
    with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
        csv_dict_reader = csv.DictReader(read_obj)
        
        # Loop through every row in CSV
        for row in csv_dict_reader:
            try:
                row_num += 1
                progress_bar(row_num, total_rows, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
            
                cwe = row['CWEs']
                if cwe is not None and isinstance(cwe, str):
                    cwe = cwe.replace('CWE-', '')
                else:
                    cwe = ''
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # CWEs are either a single entry or multiple that are comma-separated. Use the first entry.
                if len(cwe) > 0:
                    cwe = cwe.split(',')[0]
                    # Some CWEs have a slash in them, and according to documentation it is in "more-general/more-specific" format
                    # The '!' is used to denote which CWE is the one the finding mapped to. Since we only care about more-specific, we will ignore '!'
                    cwe = cwe.split('/')[-1].replace('!', '')
                
                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path = str(row['File']).replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                
                line = int(row['Line']) if str(row['Line']).isdigit() else row['Line']
                
                # Severity level
                severity = row['Level']
                if severity is not None:
                    # Documentation designates 0 as "very little risk" and 5 as "great risk"
                    try:
                        match str(severity):
                            case '0':
                                severity = f"{severity} (Very Little Risk)"
                            case '1':
                                severity = f"{severity} (Little Risk)"
                            case '2':
                                severity = f"{severity} (Medium Risk)"
                            case '3':
                                severity = f"{severity} (High Risk)"
                            case '4':
                                severity = f"{severity} (Very High Risk)"
                            case '5':
                                severity = f"{severity} (Great Risk)"
                            case _:
                                pass
                    except ValueError:
                        pass
                
                # Type
                category = row['Category']
                
                # Symbol
                symbol = row['Context']
                if not (symbol is not None and isinstance(symbol, str) and len(symbol) > 0):
                    symbol = row['Name']
                
                # Language
                lang = resolve_lang_from_ext(os.path.splitext(path)[1])
                
                # Message
                warning = row['Warning']
                suggestion = row['Suggestion']
                note = row['Note']
                message = ". ".join(part for part in [warning, suggestion, note] if len(part.strip()) > 0)
                
                # Generate ID for finding if fingerprint is not here
                fingerprint = row['Fingerprint']
                if not (fingerprint is not None and isinstance(fingerprint, str) and len(fingerprint) > 0):
                    preimage = '\0'.join(str(p) for p in (path, line, category, message) if len(str(p)) > 0)
                    fingerprint = idgenerator.hash(preimage)

                # Write row to outfile
                parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                                    Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                                    Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                                    Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                                    Fieldnames.PROPOSED_MITIGATION.value:'',
                                    Fieldnames.VALIDATOR_COMMENT.value:'',
                                    Fieldnames.ID.value:fingerprint,
                                    Fieldnames.TYPE.value:category,
                                    Fieldnames.PATH.value:path,
                                    Fieldnames.LINE.value:line,
                                    Fieldnames.SYMBOL.value:symbol,
                                    Fieldnames.MESSAGE.value:message,
                                    Fieldnames.TRACE.value:'',
                                    Fieldnames.TOOL_CWE.value:tool_cwe,
                                    Fieldnames.TOOL.value:'',
                                    Fieldnames.SCANNER.value:scanner,
                                    Fieldnames.LANGUAGE.value:lang,
                                    Fieldnames.SEVERITY.value:severity
                                })
                finding_count += 1
            except Exception:
                logger.error("Row %d of \'%s\': %s", row_num, fpath, traceback.format_exc())
                err_count += 1
    logger.info("Successfully processed %d findings", finding_count)
    logger.info("Number of erroneous rows: %d", err_count)
    return finding_count, err_count
# End of parse

def _normalize_text(s):
    return unquote(s)
