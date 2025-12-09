# checkmarx.py
import os
import logging
import traceback
import csv
import xml.etree.ElementTree as ET
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE, progress_bar
from .parser_tools.user_overrides import cwe_conf_override
from .parser_tools.toolbox import Fieldnames, console

logger = logging.getLogger(__name__)

checkmarx_cdata = []

def path_preview(fpath):
    # Parse the input file
    for file in os.listdir(fpath):
        try:
            # Check if XML or CSV
            if file.endswith('.xml'):
                # Parse the XML file
                tree = ET.parse(os.path.join(fpath, file))
                root = tree.getroot()
                preview = root.findtext('.//FileName', '')
                if len(preview) <= 0: continue
                else: return preview # Immediately return valid value
            elif file.endswith('.csv'):
                with open(os.path.join(fpath, file), "r", encoding='utf-8-sig') as read_obj:
                    csv_reader = csv.DictReader(read_obj)
                    first_row = next(csv_reader)
                    cell_preview = first_row['SrcFileName']
                    return cell_preview # Immediately return valid value
                
        except StopIteration:
            continue # Thrown by next() once a file is done iterating (i.e., it has no data)
        
        except Exception as e:
            return f"[ERROR] {e}" # Immediately return unknown exception message
    
    # No data, return error message
    return f"[ERROR] No data found in Checkmarx directory \'{fpath}\'"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Count errors encountered while running
    err_count = 0
        
    # Keep track of row number for progressbar
    i = 0
    finding_count = 0
    
    total_findings = _get_total(fpath)
    
    # Loop through directory
    for filename in os.listdir(fpath):
        # Check if the file is a csv
        if os.path.splitext(filename)[1] not in ['.xml', '.csv']:
            logger.info(f"Skipping \"{filename}\", not an xml or csv file")
            continue
        
        # Create full path with directory and filename
        f = os.path.join(fpath, filename)
        
        # Parse the file
        if f.endswith('.xml'):
            t_i, t_finding_count, t_err_count = _parse_xml(f, i, finding_count, err_count, substr, prepend, control_flags, total_findings, fpath, scanner, current_parser)
            i = t_i
            finding_count = t_finding_count
            err_count = t_err_count
        elif f.endswith('.csv'):
            t_i, t_finding_count, t_err_count = _parse_csv(f, i, finding_count, err_count, substr, prepend, control_flags, total_findings, fpath, scanner, current_parser)
            i = t_i
            finding_count = t_finding_count
            err_count = t_err_count
        else:
            logger.error(f"File {fpath} is not an XML or CSV.")
            continue
        
        
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse

def _get_total(path):
    finding_count = 0
    
    for filename in os.listdir(path):
        if os.path.splitext(filename)[1] not in ['.xml', '.csv']:
            continue
        f = os.path.join(path, filename)
        if f.endswith('.csv'):
            with open(f, mode='r', encoding='utf-8-sig') as read_obj:
                finding_count += len([row[list(row.keys())[0]] for row in csv.DictReader(read_obj)])
        else:
            tree = ET.parse(f)
            root = tree.getroot()
            queries = root.findall('Query')
            if queries is None or len(queries) <= 0:
                continue
            
            for query in queries:
                results = query.findall('Result')
                if results is None:
                    continue
                else:
                    finding_count += len(results)
    return finding_count
# End of _get_total

def _parse_csv(f, i, finding_count, err_count, substr, prepend, control_flags, total_findings, fpath, scanner, current_parser):
    from . import FLAG_CATEGORY_MAPPING, cwe_categories
    # Open csv in read
    with open(f, mode='r', encoding='utf-8-sig') as read_obj:
        csv_dict_reader = csv.DictReader(read_obj)
        
        # Keep track of row number for debug
        row_num = 0
        
        # Loop through every row in CSV
        for row in csv_dict_reader:
            row_num += 1
            try:
                i+=1
                progress_bar(i, total_findings, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
        
                # row variable is a dictionary that represents a row in csv
                lang = row['QueryPath'].split('\\')[0]

                # Check checkmarx_cdata
                cwe = get_checkmarx_cdata(row['Query'], lang)
                
                # Adjust lang
                if lang == 'CPP': lang = 'c/c++'
                else: lang = lang.lower()
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                query = row['Query']
                
                # Perform cwe overrides if user requests
                cwe, confidence = cwe_conf_override(control_flags, override_name=query, cwe=cwe, override_scanner=current_parser)
                
                # Check if cwe is in categories dict
                if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                    cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
                else:
                    cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                
                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path = str(row['SrcFileName']).replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                dest_path = str(row['DestFileName']).replace(substr, "", 1)
                dest_path = os.path.join(prepend, path).replace('\\', '/')
                
                line = int(row['Line']) if str(row['Line']).isdigit() else row['Line']
                dest_line = int(row['DestLine']) if str(row['DestLine']).isdigit() else row['DestLine']
                
                # Put Dest info in the message column
                #dest_info = f"Destination: {row['DestFileName']}:{row['DestLine']}: \"{row['DestName']}\""
            
                # Generate ID for finding
                preimage = f"{path}{row['Line']}{row['Name']}{query}{tool_cwe}{dest_path}{row['DestLine']}{row['DestName']}"
                id = idgenerator.hash(preimage)
                #id = "CX{:04}".format(finding_count+1)
                
                trace = f"Trace:\n<Source> {path}:{line}: {row['Name']}\n<Dest> {dest_path}:{dest_line}: {row['DestName']}"
                
                # Write row to outfile
                parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe_cat,
                                        Fieldnames.CONFIDENCE.value:confidence,
                                        Fieldnames.MATURITY.value:'Unreported',
                                        Fieldnames.MITIGATION.value:'',
                                        Fieldnames.PROPOSED_MITIGATION.value:'',
                                        Fieldnames.VALIDATOR_COMMENT.value:'',
                                        Fieldnames.ID.value:id,
                                        Fieldnames.TYPE.value:query,
                                        Fieldnames.PATH.value:path,
                                        Fieldnames.LINE.value:line,
                                        Fieldnames.SYMBOL.value:row['Name'],
                                        Fieldnames.MESSAGE.value:trace,
                                        Fieldnames.TOOL_CWE.value: tool_cwe,
                                        Fieldnames.TOOL.value:'',
                                        Fieldnames.SCANNER.value:scanner,
                                        Fieldnames.LANGUAGE.value:lang,
                                        Fieldnames.SEVERITY.value:row['Result Severity']
                                    })
    
                finding_count += 1
            except Exception:
                logger.error(f"Row {row_num} of \'{fpath}\': {traceback.format_exc()}")
                err_count += 1
    return i, finding_count, err_count
# End of _parse_csv

def _parse_xml(f, i, finding_count, err_count, substr, prepend, control_flags, total_findings, fpath, scanner, current_parser):
    from . import FLAG_CATEGORY_MAPPING, cwe_categories
    # Extract XML
    tree = ET.parse(f)
    root = tree.getroot()
    
    # Gather meta information
    scanner_version = root.get('CheckmarxVersion', '')
    if len(scanner_version) > 0:
        scanner = f"Checkmarx {scanner_version}"
    
    # Checkmarx is organized via query ('Type'), so iterate through all queries
    queries = root.findall('Query')
    if queries is None or len(queries) <= 0:
        return i, finding_count, err_count
    
    for query in queries:
        try:
            # Get query ID for logging purposes
            query_id = query.get('id', '')
            
            # Get query name for Type column
            query_name = query.get('name', '').replace('_', ' ').strip()
            
            # Checkmarx does provide CWE numbers. Since Checkmarx is more recently updated than the cdata file, use the checkmarx cwe first, then change to cdata if the cwe does not exist.
            cwe = query.get('cweId', '')
            query_path = query.get('QueryPath', '')
            lang = query_path.split('\\')[0]
            
            if len(cwe) <= 0:
                # Check checkmarx_cdata
                cwe = get_checkmarx_cdata(query.get('name', ''), lang)
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Adjust lang
            if lang == 'CPP': lang = 'c/c++'
            else: lang = lang.lower()
            
            # Perform cwe overrides if user requests
            cwe, confidence = cwe_conf_override(control_flags, override_name=query_name, cwe=cwe, override_scanner=current_parser)
            
            # Check if cwe is in categories dict
            if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
            else:
                cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
            
            # Iterate through every result in the query
            results = query.findall('Result')
            if results is None or len(results) <= 0:
                continue
            
            for result in results:
                i += 1
                progress_bar(i, total_findings, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
                try:
                    # Get result ID for logging purposes
                    result_id = result.get('NodeId', '')
                    
                    # Get result severity
                    severity = result.get('Severity', '')
                    
                    # Get path and line, trim path and prepend
                    path = str(result.get('FileName', '')).replace(substr, "", 1)
                    path = os.path.join(prepend, path).replace('\\', '/')
                    
                    line = result.get('Line', '')
                    line = int(line) if str(line).isdigit() else line
                    
                    # Get symbol when parsing PathNode
                    symbol = ''
                    
                    # Loop through all the PathNode tags to generate trace
                    path_nodes = result.findall('.//PathNode')
                    
                    if path_nodes is None or len(path_nodes) <= 0:
                        trace = ''
                    else:
                        trace = 'Trace:\n'
                        for node in path_nodes:
                            node_id = node.findtext('NodeId', '')
                            t_path = node.findtext('FileName', '')
                            t_line = node.findtext('Line', '')
                            t_name = node.findtext('Name', '')
                            
                            # Trim path and prepend
                            t_path = t_path.replace(substr, "", 1)
                            t_path = os.path.join(prepend, t_path).replace('\\', '/')
                            
                            if int(node_id) == 1:
                                symbol = t_name
                            
                            trace += f"{node_id}) {t_path}:{t_line}: {t_name}\n"
                        trace = trace.strip()
                            
                    
                    # Generate ID for finding
                    preimage = f"{path}{line}{query_name}{tool_cwe}{trace}"
                    id = idgenerator.hash(preimage)
                    
                    # Write row to outfile
                    parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe_cat,
                                            Fieldnames.CONFIDENCE.value:confidence,
                                            Fieldnames.MATURITY.value:'Unreported',
                                            Fieldnames.MITIGATION.value:'',
                                            Fieldnames.PROPOSED_MITIGATION.value:'',
                                            Fieldnames.VALIDATOR_COMMENT.value:'',
                                            Fieldnames.ID.value:id,
                                            Fieldnames.TYPE.value:query_name,
                                            Fieldnames.PATH.value:path,
                                            Fieldnames.LINE.value:line,
                                            Fieldnames.SYMBOL.value:symbol,
                                            Fieldnames.MESSAGE.value:trace,
                                            Fieldnames.TOOL_CWE.value: tool_cwe,
                                            Fieldnames.TOOL.value:query_path.split('\\')[-1],
                                            Fieldnames.SCANNER.value:scanner,
                                            Fieldnames.LANGUAGE.value:lang,
                                            Fieldnames.SEVERITY.value:severity
                                        })
                    finding_count += 1
                except Exception:
                    logger.error(f"Error detected in Result ID {result_id} in \'{fpath}\': {traceback.format_exc()}")
                    err_count += 1
        except Exception:
            logger.error(f"Error detected in Query ID {query_id} in \'{fpath}\': {traceback.format_exc()}")
            err_count += 1
    return i, finding_count, err_count
# End of _parse_xml

def load_checkmarx_cdata():
    from . import CONFIG_DIR
    import json
    
    try:
        with open(os.path.join(CONFIG_DIR, 'checkmarx_cdata.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
    except json.JSONDecodeError:
        console("Unable to load Checkmarx CWE mappings: Invalid JSON format\nThe program will continue without CWE mappings.", "Config Error", type='error')
        return [0]
    
def get_checkmarx_cdata(query, lang, default=''):
    # Maps pylint query to CWE number and returns it
    global checkmarx_cdata
    
    if len(checkmarx_cdata) <= 0:
        checkmarx_cdata = load_checkmarx_cdata()
    
    # Check checkmarx_cdata in cdata.py
    possible_entries = [c for c in checkmarx_cdata if c['Lang'] == lang and c['Query'] == query.replace(' ', '_')]
    
    # Return CWE # if found, else leave it blank.
    return possible_entries[0]['CWE'] if len(possible_entries) > 0 else default
