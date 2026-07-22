# checkmarx.py
import os
import logging
import traceback
import csv
import xml.etree.ElementTree as ET
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE, progress_bar
from .parser_tools.toolbox import Fieldnames, console

logger = logging.getLogger(__name__)

checkmarx_cdata = []

def path_preview(fpath):
    # Parse the input file
    try:
        # Check if XML or CSV
        if fpath.endswith('.xml'):
            # Parse the XML file
            tree = ET.parse(os.path.join(fpath, fpath))
            root = tree.getroot()
            preview = root.findtext('.//FileName', '')
            if len(preview) > 0:
                return preview # Immediately return valid value
        elif fpath.endswith('.csv'):
            with open(os.path.join(fpath, fpath), "r", encoding='utf-8-sig') as read_obj:
                csv_reader = csv.DictReader(read_obj)
                for row in csv_reader:
                    cell_preview = row.get('DestFileName', '')
                    if len(cell_preview) > 0:
                        return cell_preview # Immediately return valid value
    
    except Exception as e:
        return f"[ERROR] {e}" # Immediately return unknown exception message
    
    # No data, return error message
    return f"[ERROR] No data found in Checkmarx file \'{fpath}\'"

def parse(fpath, scanner, substr, prepend):
    logger.info("Parsing %s - %s", scanner, fpath)
    
    # Count findings and errors
    finding_count = 0
    err_count = 0
    
    total_findings = _get_total(fpath)
    
    # Parse the file
    if fpath.endswith('.xml'):
        finding_count, err_count = _parse_xml(fpath, substr, prepend, total_findings, scanner)
    elif fpath.endswith('.csv'):
        finding_count, err_count = _parse_csv(fpath, substr, prepend, total_findings, scanner)
    else:
        logger.error("File %s is not an XML or CSV.", fpath)
        
        
    logger.info("Successfully processed %d findings", finding_count)
    logger.info("Number of erroneous rows: %d", err_count)
    return finding_count, err_count
# End of parse

def _get_total(path):
    finding_count = 0
    
    if path.endswith('.csv'):
        with open(path, mode='r', encoding='utf-8-sig') as read_obj:
            finding_count = len([row[list(row.keys())[0]] for row in csv.DictReader(read_obj)])
    else:
        tree = ET.parse(path)
        root = tree.getroot()
        queries = root.findall('Query')
        if queries is None or len(queries) <= 0:
            return finding_count
        
        for query in queries:
            results = query.findall('Result')
            if results is None:
                continue
            else:
                finding_count += len(results)
    return finding_count
# End of _get_total

def _parse_csv(fpath, substr, prepend, total_findings, scanner):
    # Counts
    finding_count = 0
    err_count = 0
    
    # Open csv in read
    with open(fpath, mode='r', encoding='utf-8-sig') as read_obj:
        csv_dict_reader = csv.DictReader(read_obj)
        
        # Keep track of row number for debug
        row_num = 0
        
        # Loop through every row in CSV
        for row in csv_dict_reader:
            row_num += 1
            try:
                progress_bar(row_num, total_findings, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
        
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
                preimage = '\0'.join(str(p) for p in (path, row['Line'], row['Name'], query, tool_cwe, dest_path, row['DestLine'], row['DestName']) if len(str(p)) > 0)
                id = idgenerator.hash(preimage)
                #id = "CX{:04}".format(finding_count+1)
                
                trace = f"1) {path}:{line}: {row['Name']}\n2) {dest_path}:{dest_line}: {row['DestName']}"
                message = "{} - {}:{}: {}".format(query, dest_path, dest_line, row['DestName'])
                
                # Write row to outfile
                parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                                        Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                                        Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                                        Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                                        Fieldnames.PROPOSED_MITIGATION.value:'',
                                        Fieldnames.VALIDATOR_COMMENT.value:'',
                                        Fieldnames.ID.value:id,
                                        Fieldnames.TYPE.value:query,
                                        Fieldnames.PATH.value:dest_path,
                                        Fieldnames.LINE.value:dest_line,
                                        Fieldnames.SYMBOL.value:row['Name'],
                                        Fieldnames.MESSAGE.value:message,
                                        Fieldnames.TRACE.value:trace,
                                        Fieldnames.TOOL_CWE.value: tool_cwe,
                                        Fieldnames.TOOL.value:'',
                                        Fieldnames.SCANNER.value:scanner,
                                        Fieldnames.LANGUAGE.value:lang,
                                        Fieldnames.SEVERITY.value:row['Result Severity']
                                    })
    
                finding_count += 1
            except Exception:
                logger.error("Row %d of \'%s\': %s", row_num, fpath, traceback.format_exc())
                err_count += 1
    return finding_count, err_count
# End of _parse_csv

def _parse_xml(fpath, substr, prepend, total_findings, scanner):
    # Counts
    i = 0
    finding_count = 0
    err_count = 0
    
    # Extract XML
    tree = ET.parse(fpath)
    root = tree.getroot()
    
    # Gather meta information
    scanner_version = root.get('CheckmarxVersion', '')
    if len(scanner_version) > 0:
        scanner = f"Checkmarx {scanner_version}"
    
    # Checkmarx is organized via query ('Type'), so iterate through all queries
    queries = root.findall('Query')
    if queries is None or len(queries) <= 0:
        return finding_count, err_count
    
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
                    
                    # Set message to the last entry of trace
                    message = ''
                    
                    # Loop through all the PathNode tags to generate trace
                    path_nodes = result.findall('.//PathNode')
                    
                    if path_nodes is None or len(path_nodes) <= 0:
                        trace = ''
                    else:
                        trace = ''
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
                            
                            # Update t_path and t_line to be dest path/line if it exists and is a number
                            if t_path is not None and len(str(t_path)) > 0:
                                path = t_path
                            
                            if t_line is not None and len(str(t_line)) > 0 and str(t_line).isdigit():
                                line = int(t_line)
                            
                            trace += f"{node_id}) {t_path}:{t_line}: {t_name}\n"
                        message = "{} - {}:{}: {}".format(query_name, path_nodes[-1].findtext('FileName', ''), path_nodes[-1].findtext('Line', ''), path_nodes[-1].findtext('Name', ''))
                        trace = trace.strip()
                            
                    
                    # Generate ID for finding
                    preimage = '\0'.join(str(p) for p in (path, line, query_name, tool_cwe, trace) if len(str(p)) > 0)
                    id = idgenerator.hash(preimage)
                    
                    # Write row to outfile
                    parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                                            Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                                            Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                                            Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                                            Fieldnames.PROPOSED_MITIGATION.value:'',
                                            Fieldnames.VALIDATOR_COMMENT.value:'',
                                            Fieldnames.ID.value:id,
                                            Fieldnames.TYPE.value:query_name,
                                            Fieldnames.PATH.value:path,
                                            Fieldnames.LINE.value:line,
                                            Fieldnames.SYMBOL.value:symbol,
                                            Fieldnames.MESSAGE.value:message,
                                            Fieldnames.TRACE.value:trace,
                                            Fieldnames.TOOL_CWE.value: tool_cwe,
                                            Fieldnames.TOOL.value:query_path.split('\\')[-1],
                                            Fieldnames.SCANNER.value:scanner,
                                            Fieldnames.LANGUAGE.value:lang,
                                            Fieldnames.SEVERITY.value:severity
                                        })
                    finding_count += 1
                except Exception:
                    logger.error("Error detected in Result ID %s in \'%s\': %s", result_id, fpath, traceback.format_exc())
                    err_count += 1
        except Exception:
            logger.error("Error detected in Query ID %s in \'%s\': %s", query_id, fpath, traceback.format_exc())
            err_count += 1
    return finding_count, err_count
# End of _parse_xml

def load_checkmarx_cdata():
    from . import PROG_NAME_ABBR, MAPPINGS_DIR
    import json
    
    try:
        with open(os.path.join(MAPPINGS_DIR, 'checkmarx_cdata.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
    except (FileNotFoundError, json.JSONDecodeError):
        console(f"Unable to load Checkmarx CWE mappings: Invalid JSON format\n{PROG_NAME_ABBR} will continue without CWE mappings.", "Config Error", level='error', orig_name=__name__)
        return [0]
    
def get_checkmarx_cdata(query, lang, default=''):
    # Maps checkmarx query to CWE number and returns it
    global checkmarx_cdata
    
    if len(checkmarx_cdata) <= 0:
        checkmarx_cdata = load_checkmarx_cdata()
    
    # Check checkmarx_cdata in cdata.py
    possible_entries = [c for c in checkmarx_cdata if c['Lang'] == lang and c['Query'] == query.replace(' ', '_')]
    
    # Return CWE # if found, else leave it blank.
    return possible_entries[0]['CWE'] if len(possible_entries) > 0 else default
