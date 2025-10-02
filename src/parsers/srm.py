# srm.py
import os
import logging
import traceback
import csv
import xml.etree.ElementTree as ET
from . import FLAG_CATEGORY_MAPPING, cwe_categories
from .pylint import get_pylint_cdata
from .parser_tools import idgenerator, parser_writer
from .parser_tools.language_resolver import resolve_lang
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.user_overrides import cwe_conf_override

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    try:
        # Parse the XML file
        tree = ET.parse(fpath)
        root = tree.getroot()
        findings = root.find('findings')
        
        for finding in findings:
            location = finding.find('location')
            if location.get('type') != 'file': continue
            
            path = location.get('path', '')
            if len(path) <= 0: continue
            else: return path
        
    except Exception as e:
        return f"[ERROR] {e}"

def path_preview(fpath):
    # Parse the input file
    try:
        # Check if XML or CSV
        if fpath.endswith('.xml'):
            # Parse the XML file
            tree = ET.parse(fpath)
            root = tree.getroot()
            findings = root.find('findings')
            
            for finding in findings:
                location = finding.find('location')
                if location.get('type') != 'file': continue
                
                path = location.get('path', '')
                if len(path) <= 0: continue
                else: return path
        elif fpath.endswith('.csv'):
            with open(fpath, "r", encoding='utf-8-sig') as read_obj:
                csv_reader = csv.DictReader(read_obj)
                first_row = next(csv_reader)
                cell_preview = first_row['Path']
                return cell_preview
        else:
            return "[ERROR] Unsupported file type for SRM"
    except StopIteration:
        pass # Thrown by next() once a CSV file is done iterating (i.e., it has no data)
    
    except Exception as e:
        return f"[ERROR] {e}" # Immediately return unknown exception message
    
    # No data, return error message
    return f"[ERROR] No data found in \'{fpath}\'"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Keep track of issue number and errors
    finding_count = 0
    err_count = 0
    
    # Parse the file
    if fpath.endswith('.xml'):
        finding_count, err_count = _parse_xml(fpath, substr, prepend, control_flags, scanner, current_parser)
    elif fpath.endswith('.csv'):
        finding_count, err_count = _parse_csv(fpath, substr, prepend, control_flags, scanner, current_parser)
    else:
        logger.error(f"File {fpath} is not an XML or CSV.")
        return err_count + 1
    
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse


def _parse_csv(fpath, substr, prepend, control_flags, scanner, current_parser):
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
            
                # Resolve language of the file
                lang = resolve_lang(os.path.splitext(row['Path'])[1])
                
                cwe = row['CWE']
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # Perform cwe overrides if user requests
                cwe, confidence = cwe_conf_override(control_flags, override_name=row['Type'], cwe=cwe, override_scanner=current_parser)
                
                # Check if cwe is in categories dict
                if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                    cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
                else:
                    cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                
                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path = str(row['Path']).replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                
                line = int(row['Line']) if str(row['Line']).isdigit() else row['Line']
                
                # Generate ID for finding (concat Path, Line, Scanner, and Type)
                preimage = f"{path}{row['Line']}{row['Type']}{tool_cwe}"
                id = idgenerator.hash(preimage)
                #id = "SRM{:04}".format(finding_count+1)

                # Write row to outfile
                parser_writer.write_row({'CWE':cwe_cat,
                                    'Confidence':confidence,
                                    'Maturity':'Proof of Concept',
                                    'Mitigation':'None',
                                    'Mitigation Comment':'',
                                    'Comment':'',
                                    'ID':id,
                                    'Type':row['Type'],
                                    'Path':path,
                                    'Line':line,
                                    'Symbol':'',
                                    'Message':'',
                                    'Tool CWE':tool_cwe,
                                    'Tool':row['Tool'],
                                    'Scanner':scanner,
                                    'Language':lang,
                                    'Severity':''
                                })
                finding_count += 1
            except Exception:
                logger.error(f"Row {row_num} of \'{fpath}\': {traceback.format_exc()}")
                err_count += 1
    return finding_count, err_count
# End of _parse_csv

def _parse_xml(fpath, substr, prepend, control_flags, scanner, current_parser):
    # Keep track of issue number and errors
    finding_num = 0
    finding_count = 0
    err_count = 0
    
    # Parse the XML file
    tree = ET.parse(fpath)
    root = tree.getroot()
    findings = root.find('findings')
    
    # Gather meta information
    scanner_version = root.get('generator-version')
    scanner = f"SRM v{scanner_version}"
    
    # Get total number of findings
    total_findings = len(findings)
    
    for finding in findings:
        finding_num += 1
        try:
            progress_bar(finding_num, total_findings, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
            
            # Get finding ID for logging
            finding_id = finding.get('id', '')
        
            # Get path/line and resolve language
            location = finding.find('location')
            path = location.get('path', '')
            line_xml = location.find('line')
            line = line_xml.get('end', line_xml.get('start', ''))
            line = int(line) if str(line).isdigit() else line
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = path.replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            # Resolve language of the file
            lang = resolve_lang(os.path.splitext(path)[1])
            
            # Get cwe
            if finding.find('cwe') is not None:
                cwe = finding.find('cwe').get('id', '')
            else:
                cwe = ''
            
            # Now iterate through results tag
            for result in finding.find('results'):
                
                # Check if the scanner is pylint, change cwe number if so
                tool = result.find('tool')
                tool_name = tool.get('name', '')
                rule = tool.find('rule')
                
                if tool_name.lower() == 'pylint':
                    message_id = rule.get('code', '').replace('PYLINT-', '').upper()
                    cwe = get_pylint_cdata(message_id, cwe)
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # Get finding 'Type'
                finding_type = rule.get('name', '')
                
                # Perform cwe overrides if user requests
                cwe, confidence = cwe_conf_override(control_flags, override_name=finding_type, cwe=cwe, override_scanner=current_parser)
                
                # Check if cwe is in categories dict
                if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                    cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
                else:
                    cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                    
                # Get the description
                trace = result.findtext('description', '')
                
                # Get trace if dataflow tag exists
                dataflow = result.find('dataflows/dataflow')
                if dataflow is not None:
                    nodes = dataflow.findall('node')
                    if nodes is not None and len(nodes) > 0:
                        trace = trace+'\n' if len(trace) > 0 else trace
                        trace += 'Trace:\n'
                        
                        # Cap length to 8 entries
                        if len(nodes) > 8:
                            iteratable = nodes[:3] + ['...'] + nodes[-5:]
                        else: iteratable = nodes
                        
                        for i, node in enumerate(iteratable, start=1):
                            if node == '...':
                                trace += "...\n"
                                continue
                            remark = node.findtext('remark', '')
                            loc = node.find('location')
                            t_path = loc.get('path', '')
                            t_line_xml = location.find('line')
                            t_line = t_line_xml.get('end', t_line_xml.get('start', ''))
                            
                            # Cut and prepend the paths and convert all backslashes to forwardslashes
                            t_path = t_path.replace(substr, "", 1)
                            t_path = os.path.join(prepend, t_path).replace('\\', '/')
                            
                            # Append to trace
                            trace += f"{i}) {t_path}:{t_line}: {remark}\n"
                trace = trace.strip()
                
                
                # Use the SHA256 hash from the finding as the ID, else generate the ID
                id = result.get('hash', '')
                if len(id) <= 0:
                    preimage = f"{path}{line}{finding_type}{tool_cwe}"
                    id = idgenerator.hash(preimage)

                # Write row to outfile
                parser_writer.write_row({'CWE':cwe_cat,
                                    'Confidence':confidence,
                                    'Maturity':'Proof of Concept',
                                    'Mitigation':'None',
                                    'Mitigation Comment':'',
                                    'Comment':'',
                                    'ID':id,
                                    'Type':finding_type,
                                    'Path':path,
                                    'Line':line,
                                    'Symbol':'',
                                    'Message':trace,
                                    'Tool CWE':tool_cwe,
                                    'Tool':tool_name,
                                    'Scanner':scanner,
                                    'Language':lang,
                                    'Severity':''
                                })
            finding_count += 1
        except Exception:
            logger.error(f"Finding with ID {finding_id} in \'{fpath}\': {traceback.format_exc()}")
            err_count += 1
    return finding_count, err_count
# End of _parse_xml
