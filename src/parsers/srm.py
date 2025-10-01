# srm.py
import os
import logging
import traceback
import xml.etree.ElementTree as ET
from . import FLAG_VULN_MAPPING
from .parser_tools import idgenerator, parser_writer
from .parser_tools.cwe_categories import cwe_categories
from .parser_tools.pylint_cdata import pylint_cdata
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

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Keep track of issue number and errors
    finding_num = 0
    total_findings = 0
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
                    if message_id in pylint_cdata.keys():
                        cwe = pylint_cdata[message_id]
                    elif message_id[0] == 'R':
                        cwe = '710'
                    elif message_id[0] == 'C':
                        cwe = '1076'
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # Get finding 'Type'
                finding_type = rule.get('name', '')
                
                # Perform cwe overrides if user requests
                cwe, confidence = cwe_conf_override(control_flags, override_name=finding_type, cwe=cwe, override_scanner=current_parser)
                
                # Check if cwe is in categories dict
                if control_flags[FLAG_VULN_MAPPING] and cwe in cwe_categories.keys():
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
    
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous rows: {err_count}")
    return err_count
# End of parse
