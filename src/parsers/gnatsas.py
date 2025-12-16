# gnatsas.py
import os
import logging
import csv
import json
import re
import traceback
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override
from .parser_tools.toolbox import Fieldnames

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    try:
        if fpath.endswith('.csv'):
            with open(fpath, "r", encoding='utf-8-sig') as read_obj:
                csv_reader = csv.DictReader(read_obj)
                first_row = next(csv_reader)
                cell_preview = first_row['path']
                return cell_preview
        else:
            with open(fpath, "r", encoding='utf-8-sig') as read_obj:
                data = json.load(read_obj)
            # Keep going until valid path is found
            for r in data['runs'][0]['results']:
                try:
                    return r['locations'][0]['physicalLocation']['artifactLocation']['uri']
                except KeyError:
                    continue
            return "[ERROR] No paths found in input file."
    except json.JSONDecodeError:
        return "[ERROR] Improperly formatted input file. Ensure GNAT SAS is configured to output in SARIF format."
    except Exception as e:
        return f"[ERROR] {e}"

def parse(fpath, scanner, substr, prepend, control_flags):
    logger.info(f"Parsing {scanner} - {fpath}")
    
    if fpath.endswith('.csv'):
        finding_count, err_count = _parse_csv(fpath, scanner, substr, prepend, control_flags)
    else:
        finding_count, err_count = _parse_sarif(fpath, scanner, substr, prepend, control_flags)
    
    
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse

def _parse_sarif(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    from . import FLAG_CATEGORY_MAPPING, cwe_categories
    
    finding_count = 0
    result_num = 0
    
    # Count errors encountered while running
    err_count = 0
    
    # Load data
    try:
        with open(fpath, "r", encoding='utf-8-sig') as read_obj:
            data = json.load(read_obj)
    except json.JSONDecodeError:
        err_count += 1
        logger.error(f"Unable to parse input file \"{fpath}\". Ensure GNAT SAS is configured to output in SARIF format.")
        return finding_count, err_count
    
    # Get just data
    data = data['runs'][0]
    
    # Get total number of findings
    total_results = len(data['results'])
    
    # Get metadata
    o_scanner = data['tool']['driver']['version']
    
    # Iterate through results
    for result in data['results']:
        try:
            fingerprint_checksum = result['fingerprints']['checksum']
            result_num += 1
            if progress_bar(scanner, result_num, total_results, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE)):
                return err_count
        
            # Type
            t = result['ruleId']
        
            # Get CWE
            cwe = ''
            for taxa in result.get('taxa', []):
                if taxa['toolComponent'].get('name', '').upper() == "CWE":
                   cwe += taxa.get('id', '').replace('CWE', '') + ','
            cwe = cwe.rstrip(',')
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else:
                tool_cwe = int(cwe.split(',')[0]) if len(cwe.split(',')) > 1 and str(cwe.split(',')[0]).isdigit() else cwe
                cwe = int(cwe.split(',')[0])
            
            # Perform cwe overrides if user requests
            cwe, confidence = cwe_conf_override(control_flags, override_name=t, cwe=cwe, override_scanner=current_parser)
            
            # Check if cwe is in categories dict
            if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
            else:
                cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
            
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = str(result['locations'][0]['physicalLocation']['artifactLocation']['uri']).replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            line = str(result['locations'][0]['physicalLocation']['region']['startLine'])
            line = int(line) if line.isdigit() else line
            
            # Language
            lang = result['locations'][0]['physicalLocation']['region'].get('sourceLanguage', 'ada').lower()
            
            # Symbol
            symbol = result['locations'][0]['logicalLocations'][0]['fullyQualifiedName']
            
            # Severity
            severity = result['level']
            
            # Tool
            tool = ''
            for rule in data['tool']['driver']['rules']:
                if t == rule['id']:
                    if m := re.search(r'(\w+) - .*', rule['name']):
                       tool = m.group(1)
                       break
            
            # Message
            message = result['message']['text']
            if 'codeFlows' in result.keys() and 'threadFlows' in result['codeFlows'][0]:
                threadflow = result['codeFlows'][0]['threadFlows'][0]
                if len(threadflow['locations']) > 1:
                    message += '\nTrace:\n'
                    
                    # If more than 8 locations, take first 3 and last 5
                    gap_dist = 0
                    if len(threadflow['locations']) > 8:
                        beg = max(3, len(threadflow['locations'])-5)
                        end = max(3, len(threadflow['locations'])-1)
                        gap_dist = beg-2
                        locations = threadflow['locations'][:3] + ['...'] + threadflow['locations'][beg:end+1]
                    else:
                        locations = threadflow['locations']
                    
                    activate_gap_add = False
                    for i, loc in enumerate(locations, start=1):
                        if isinstance(loc, str) and loc == '...':
                            message += '...\n'
                            activate_gap_add = True
                            continue
                        
                        # Sometimes there's a lot of '../' to reference codepeer files. Strip those.
                        t_path = str(loc['location']['physicalLocation']['artifactLocation']['uri'])
                        if t_path.count('../') > 4 or t_path.count('..\\') > 4:
                            t_path = re.sub(r'^(?:\.\./)+', '/', t_path)
                        else:
                            t_path = t_path.replace(substr, "", 1)
                            t_path = os.path.join(prepend, t_path).replace('\\', '/')
                        
                        t_line = str(loc['location']['physicalLocation']['region']['startLine'])
                        t_line = int(t_line) if t_line.isdigit() else t_line
                        
                        k = i+gap_dist if activate_gap_add else i
                        message += f"{k}) {t_path}:{t_line}: {loc['location']['message'].get('text', '')}".rstrip(': ') + '\n'
            message = message.strip()
            
            
            # Generate ID for Coverity finding (concat Path, Line, Scanner, and Message)
            preimage = f"{path}{line}{t}{message}"
            id = idgenerator.hash(preimage)
            #id = "GS{:04}".format(finding_count+1)

            # Write row to outfile
            parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe_cat,
                                Fieldnames.CONFIDENCE.value:confidence,
                                Fieldnames.MATURITY.value:'Unreported',
                                Fieldnames.MITIGATION.value:'',
                                Fieldnames.PROPOSED_MITIGATION.value:'',
                                Fieldnames.VALIDATOR_COMMENT.value:'',
                                Fieldnames.ID.value:id,
                                Fieldnames.TYPE.value: t,
                                Fieldnames.PATH.value:path,
                                Fieldnames.LINE.value:line,
                                Fieldnames.SYMBOL.value:symbol,
                                Fieldnames.MESSAGE.value:message,
                                Fieldnames.TOOL_CWE.value:tool_cwe,
                                Fieldnames.TOOL.value:tool,
                                Fieldnames.SCANNER.value:o_scanner,
                                Fieldnames.LANGUAGE.value:lang,
                                Fieldnames.SEVERITY.value:severity
                            })
            finding_count += 1
        except Exception:
            logger.error(f"Result with fingerprint checksum \"{fingerprint_checksum}\" in \'{fpath}\': {traceback.format_exc()}")
            err_count += 1
        
    return finding_count, err_count
# End of _parse_sarif


def _parse_csv(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    from . import FLAG_CATEGORY_MAPPING, cwe_categories
    
    # Count errors encountered while running
    err_count = 0
    
    # Keep track of row number for debug
    row_num = 0
    finding_count = 0
    total_rows = 0
    
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
                if progress_bar(scanner, row_num, total_rows, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE)):
                    return err_count
            
                cwe = row['cwe']
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # Perform cwe overrides if user requests
                cwe, confidence = cwe_conf_override(control_flags, override_name=row['kind'], cwe=cwe, override_scanner=current_parser)
                
                # Check if cwe is in categories dict
                if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                    cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
                else:
                    cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                
                # Type
                if len(row['related_checks']) > 0:
                    t = row['kind'] + ": " + row['related_checks']
                else:
                    t = row['kind']
                
                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path = str(row['path']).replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                
                line = int(row['line']) if str(row['line']).isdigit() else row['line']
                
                # Generate ID for Coverity finding (concat Path, Line, Scanner, and Message)
                preimage = f"{path}{line}{t}{row['message']}"
                id = idgenerator.hash(preimage)
                #id = "GS{:04}".format(finding_count+1)

                # Write row to outfile
                parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe_cat,
                                    Fieldnames.CONFIDENCE.value:confidence,
                                    Fieldnames.MATURITY.value:'Unreported',
                                    Fieldnames.MITIGATION.value:'',
                                    Fieldnames.PROPOSED_MITIGATION.value:'',
                                    Fieldnames.VALIDATOR_COMMENT.value:'',
                                    Fieldnames.ID.value:id,
                                    Fieldnames.TYPE.value: t,
                                    Fieldnames.PATH.value:path,
                                    Fieldnames.LINE.value:line,
                                    Fieldnames.SYMBOL.value:row['subp'],
                                    Fieldnames.MESSAGE.value:row['message'],
                                    Fieldnames.TOOL_CWE.value:tool_cwe,
                                    Fieldnames.TOOL.value:row['tool'],
                                    Fieldnames.SCANNER.value:scanner,
                                    Fieldnames.LANGUAGE.value:'ada',
                                    Fieldnames.SEVERITY.value:''
                                })
                finding_count += 1
            except Exception:
                logger.error(f"Row {row_num} of \'{fpath}\': {traceback.format_exc()}")
                err_count += 1
    return finding_count, err_count
# End of _parse_csv