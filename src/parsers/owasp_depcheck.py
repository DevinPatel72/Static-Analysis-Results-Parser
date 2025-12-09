# owasp_depcheck.py

import os
import re
import logging
import csv
import json
import traceback
from .parser_tools import idgenerator, parser_writer
from .parser_tools.user_overrides import cwe_conf_override
from .parser_tools.language_resolver import resolve_lang
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    try:
        if fpath.endswith('.csv'):
            with open(fpath, "r", encoding='utf-8-sig') as read_obj:
                # Determine deliminator character
                sep_line = read_obj.readline()
                
                if sep_line.startswith('sep='):
                    delim = sep_line.strip().split('=')[1]
                else:
                    read_obj.seek(0)
                    delim = ','
                
                # Read first row of csv
                csv_reader = csv.DictReader(read_obj, delimiter=delim)
                first_row = next(csv_reader)
                cell_preview = first_row['DependencyPath']
                return cell_preview
        else:
            with open(fpath, "r", encoding='utf-8-sig') as read_obj:
                data = json.load(read_obj)
            for dep in data['dependencies']:
                if 'filePath' in dep.keys():
                    return dep['filePath']
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
        finding_count, err_count = _parse_json(fpath, scanner, substr, prepend, control_flags)
    
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse


def _parse_json(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    
    # Keep track of row number and error count
    vuln_number = 0
    total_vulns = 0
    finding_count = 0
    err_count = 0
    
    # Track duplicate CVEs
    written_cves = []
    
    # Load data
    try:
        with open(fpath, "r", encoding='utf-8-sig') as read_obj:
            data = json.load(read_obj)
    except json.JSONDecodeError:
        err_count += 1
        logger.error(f"Unable to parse input file \"{fpath}\". Ensure Dependency Check output the file as JSON or CSV.")
        return finding_count, err_count
    
    
    # Get metadata
    if len(data['scanInfo'].get('engineVersion', '')) != 0:
        scanner = "OWASP Dependency Check {}".format(data['scanInfo']['engineVersion'])
    
    # Get total number of findings
    for dep in data['dependencies']:
        for vuln in dep.get('vulnerabilities', []):
            total_vulns += 1
    
    # Iterate through data
    for dep in data['dependencies']:
        try:
            dependency_hash = dep.get('sha256', '')
            dependency_name = dep['fileName']
            path = dep['filePath']
            line = ''
            path = path.replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            for vuln in dep.get('vulnerabilities', []):
                vuln_number += 1
                progress_bar(vuln_number, total_vulns, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
                
                # Extract CWE
                cwe = vuln.get('cwes', '')
                
                # Extract CVE
                cve = vuln['name']
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else:
                    tool_cwe = ",".join([c.replace('CWE-', '') for c in cwe])
                    
                # Get Message
                message = vuln.get('description', '')
                    
                # Perform cwe overrides if user requests
                cve, confidence = cwe_conf_override(control_flags, override_name=cve, cwe=cve, message_content=message, override_scanner=current_parser)
                
                # Generate ID for Fortify finding (concat CVE, CWE, Path, Scanner, and Vulnerability)
                preimage = f"{cve}{path}{message}"
                id = idgenerator.hash(preimage)
                #id = "DEP{:04}".format(finding_count+1)
                
                # Resolve language of the file
                lang = resolve_lang(os.path.splitext(path)[1])
                
                # Resolve Severity
                severity = vuln.get('severity', '')
                
                # Perform the duplicate CVE check last to ensure overrides are processed first
                if cve in written_cves:
                    confidence = 'DUPLICATE'
                else:
                    written_cves.append(cve)
                
                # Write row to outfile
                parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cve,
                                    Fieldnames.CONFIDENCE.value:confidence,
                                    Fieldnames.MATURITY.value:'Proof of Concept',
                                    Fieldnames.MITIGATION.value:'',
                                    Fieldnames.PROPOSED_MITIGATION.value:'',
                                    Fieldnames.VALIDATOR_COMMENT.value:'',
                                    Fieldnames.ID.value:id,
                                    Fieldnames.TYPE.value: '',
                                    Fieldnames.PATH.value:path,
                                    Fieldnames.LINE.value:line,
                                    Fieldnames.SYMBOL.value:dependency_name,
                                    Fieldnames.MESSAGE.value:message,
                                    Fieldnames.TOOL_CWE.value:tool_cwe,
                                    Fieldnames.TOOL.value:'',
                                    Fieldnames.SCANNER.value:scanner,
                                    Fieldnames.LANGUAGE.value:lang,
                                    Fieldnames.SEVERITY.value:severity
                                })
                finding_count += 1
        except Exception:
            logger.error(f"Dependency \"{dependency_name}\" with hash SHA256-{dependency_hash} in \'{fpath}\': {traceback.format_exc()}")
            err_count += 1
    return finding_count, err_count
    
    
    
# End of _parse_json

def _parse_csv(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    
    # Keep track of row number and error count
    row_num = 0
    total_rows = 0
    finding_count = 0
    err_count = 0
    
    # Keep track of CVEs to ensure no duplicate ones are created
    written_cves = []
    
    # Get total number of findings
    with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
        sep_line = read_obj.readline()
        
        if sep_line.startswith('sep='):
            delim = sep_line.strip().split('=')[1]
        else:
            read_obj.seek(0)
            delim = ','
        
        total_rows = len([row[list(row.keys())[0]] for row in csv.DictReader(read_obj, delimiter=delim)])
    
    
    # Open csv in read
    with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
        # Determine deliminator character
        sep_line = read_obj.readline()
        
        if sep_line.startswith('sep='):
            delim = sep_line.strip().split('=')[1]
        else:
            read_obj.seek(0)
            delim = ','
        
        csv_dict_reader = csv.DictReader(read_obj, delimiter=delim)
        
        # Loop through every row in CSV
        for row in csv_dict_reader:
            try:
                row_num += 1
                progress_bar(row_num, total_rows, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
                
                # Extract CWE
                cwe = row['CWE']
                if m := re.search(r'^CWE-(\d{1,4})', cwe):
                    cwe = m.group(1)
                else: cwe = ''
                
                # Extract CVE
                cve = row['CVE']
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path = row['DependencyPath']
                line = ''
                path = path.replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                
                # Resolve language of the file
                lang = resolve_lang(os.path.splitext(path)[1])
                
                # Perform cwe overrides if user requests
                cve, confidence = cwe_conf_override(control_flags, override_name=cve, cwe=cve, message_content=row['Vulnerability'], override_scanner=current_parser)
                
                # Generate ID for Fortify finding (concat CVE, CWE, Path, Scanner, and Vulnerability)
                preimage = f"{cve}{path}{row['Vulnerability']}"
                id = idgenerator.hash(preimage)
                #id = "DEP{:04}".format(finding_count+1)
                
                # Resolve Severity
                severity = row.get('CVSSv3_BaseSeverity', row.get('CVSSv2_Severity', ''))
                
                # Perform the duplicate CVE check last to ensure overrides are processed first
                if cve in written_cves:
                    confidence = 'DUPLICATE'
                else:
                    written_cves.append(cve)
                
                # Quick check to ensure CVE is actually a CVE since OWASP puts jquery errors in the data
                if not (re.match(r'^CVE-\d{4}-\d+$', cve)):
                    err_count += 1
                    logger.error(f"Row {row_num} of \'{fpath}\': Invalid CVE number. Please check \'{fpath}\' and the user overrides.")

                # Write row to outfile
                parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cve,
                                    Fieldnames.CONFIDENCE.value:confidence,
                                    Fieldnames.MATURITY.value:'Proof of Concept',
                                    Fieldnames.MITIGATION.value:'',
                                    Fieldnames.PROPOSED_MITIGATION.value:'',
                                    Fieldnames.VALIDATOR_COMMENT.value:'',
                                    Fieldnames.ID.value:id,
                                    Fieldnames.TYPE.value: '',
                                    Fieldnames.PATH.value:path,
                                    Fieldnames.LINE.value:line,
                                    Fieldnames.SYMBOL.value:row['DependencyName'],
                                    Fieldnames.MESSAGE.value:row['Vulnerability'],
                                    Fieldnames.TOOL_CWE.value:tool_cwe,
                                    Fieldnames.TOOL.value:'',
                                    Fieldnames.SCANNER.value:scanner,
                                    Fieldnames.LANGUAGE.value:lang,
                                    Fieldnames.SEVERITY.value:severity
                                })
                finding_count += 1
            except Exception:
                logger.error(f"Row {row_num} of \'{fpath}\': {traceback.format_exc()}")
                err_count += 1
    return finding_count, err_count
# End of _parse_csv