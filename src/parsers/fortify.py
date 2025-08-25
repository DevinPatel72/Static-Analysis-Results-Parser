# fortify.py

import os
import logging
import traceback
import xml.etree.ElementTree as ET
import zipfile
import tempfile
import re
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
        # Create a temporary directory to extract files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract the FPR archive
            with zipfile.ZipFile(fpath, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            # Locate the audit.fvdl file
            fvdl_path = os.path.join(temp_dir, "audit.fvdl")
            if not os.path.exists(fvdl_path):
                return "[ERROR]  audit.fvdl not found in the provided FPR file"

            # Parse the audit.fvdl file
            tree = ET.parse(fvdl_path)
            root = tree.getroot()
            namespace = {'ns': 'xmlns://www.fortifysoftware.com/schema/fvdl'}

            # Extract base path for source files
            source_base_path_elem = root.find('.//ns:SourceBasePath', namespace)
            source_base_path = source_base_path_elem.text if source_base_path_elem is not None and source_base_path_elem.text is not None else ""
            
            # Extract path from first finding
            try:
                vulnerability = root.find('.//ns:Vulnerability', namespace)
                entries = vulnerability.findall('./ns:AnalysisInfo/ns:Unified/ns:Trace/ns:Primary/ns:Entry', namespace)
                if len(entries) <= 0:
                    class_id = vulnerability.find('./ns:ClassInfo/ns:ClassID', namespace).text
                    return f"No entries found for vulnerability \"{class_id}\""
                last_entry = entries[-1]
                srcLocation = last_entry.find("./ns:Node/ns:SourceLocation", namespace)
                file_path = srcLocation.get('path')
                path = os.path.join(source_base_path, file_path) if len(source_base_path) > 0 else file_path
            except:
                logger.error("Unable to load preview.\n" + traceback.print_exc())
                return "[ERROR] Unable to load preview. See log file for details."
            
            return path
    except Exception:
        return f"[ERROR] {traceback.print_exc()}"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Count errors encountered while running
    err_count = 0
    vulnerability_num = 0
    total_vulnerabilities = 0
    finding_count = 0
    
    # Create a temporary directory to extract files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Extract the FPR archive
        with zipfile.ZipFile(fpath, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        # Locate the audit.fvdl file
        fvdl_path = os.path.join(temp_dir, "audit.fvdl")
        if not os.path.exists(fvdl_path):
            logger.critical("audit.fvdl not found in the provided FPR file. Skipping fortify parsing.")
            return err_count + 1

        # Parse the audit.fvdl file
        tree = ET.parse(fvdl_path)
        root = tree.getroot()
        namespace = {'ns': 'xmlns://www.fortifysoftware.com/schema/fvdl'}
        
        # Check if there are vulnerabilities to read
        total_vulnerabilities = len(root.findall('.//ns:Vulnerability', namespace))
        if total_vulnerabilities <= 0:
            logger.error(f"No vulnerabilities found in the FPR file \"{fpath}\". Skipping the file.")
            return err_count + 1

        # Extract base path for source files
        source_base_path_elem = root.find('.//ns:SourceBasePath', namespace)
        source_base_path = source_base_path_elem.text if source_base_path_elem is not None and source_base_path_elem.text is not None else ""

        # Extract vulnerability data
        for vulnerability in root.findall('.//ns:Vulnerability', namespace):
            try:
                vulnerability_num += 1
                progress_bar(vulnerability_num, total_vulnerabilities, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
                
                # Extract class information
                class_info = vulnerability.find('./ns:ClassInfo', namespace)
                vulnerability_type = class_info.find('ns:Type', namespace).text
                class_id = class_info.find('ns:ClassID', namespace).text
                analyzer = class_info.find('ns:AnalyzerName', namespace).text

                # Extract instance information
                instance_info = vulnerability.find('./ns:InstanceInfo', namespace)
                severity = instance_info.find('ns:InstanceSeverity', namespace).text
                
                # Severity is reported in a range 1-5 with the assumption that 5 is critical and 1 is info
                try:
                    if   0 <= float(severity) <= 1: severity = f"{severity} (Info)"
                    elif 1 < float(severity) <= 2: severity = f"{severity} (Low)"
                    elif 2 < float(severity) <= 3: severity = f"{severity} (Medium)"
                    elif 3 < float(severity) <= 4: severity = f"{severity} (High)"
                    elif 4 < float(severity) <= 5: severity = f"{severity} (Critical)"
                except ValueError:
                    pass
                
                entries_info = vulnerability.findall('./ns:AnalysisInfo/ns:Unified/ns:Trace/ns:Primary/ns:Entry', namespace)
                
                # Check if entries are found. If no entries are found, it is likely a bad vulnerability.
                if len(entries_info) <= 0:
                    err_count += 1
                    logger.error(f"Vulnerability '{class_id}' has no Entry tags. Manually unzip the .fpr file and check the audit.fvdl file for the vulnerability with classID '{class_id}' for any problems.")
                    continue
                
                # Take first 3 events and the 5 events prior to the last if it is larger than 8
                if len(entries_info) > 8:
                    events = entries_info[:3] + ['...'] + entries_info[-5:]
                else: events = entries_info
                
                # Last entry is the main finding, include the rest of the entries in the message
                last_entry_info = events[-1]
                srcLocation = last_entry_info.find("./ns:Node/ns:SourceLocation", namespace)
                file_path = srcLocation.get('path')
                line = srcLocation.get('line')
                
                # Get true rule ID from last_entry, otherwise leave it as class ID
                try:
                    rule_id = last_entry_info.find('ns:Node/ns:Reason/ns:Rule', namespace).get('ruleID')
                except:
                    rule_id = class_id
                
                
                # Extract replacement defs for the description
                replacement_defs = {}
                replacement_defs_tree = vulnerability.findall('./ns:AnalysisInfo/ns:Unified/ns:ReplacementDefinitions/ns:Def', namespace)
                for definition in replacement_defs_tree:
                    replacement_defs[str(definition.get('key'))] = str(definition.get('value'))
                
                # Extract description
                description = ''
                for desc in root.findall('.//ns:Description', namespace):
                    # Description is in its own section. Search for it using the rule_id
                    if desc.get('classID') == rule_id:
                        description = ET.tostring(desc.find('ns:Abstract', namespace), encoding='unicode', method='text').strip()
                        
                        # Replace all replacement definitions here
                        replace_key_pattern = r'<Replace key="(.+?)"/>'
                        matches = re.findall(replace_key_pattern, description)
                        for m in matches:
                            try:
                                description = description.replace(f"<Replace key=\"{m}\"/>", replacement_defs[m])
                            except KeyError:
                                err_count += 1
                                logger.warning(f"Vulnerability {vulnerability_num} (Rule ID: {rule_id}) does not have a replacement definition for key '{m}'. All keys for '{m}' in the message column will be output as '[[{m}]]'")
                                description = description.replace(f"<Replace key=\"{m}\"/>", f"[[{m}]]")
                        description = re.sub("</?(Content|Paragraph|AltParagraph|code)>", '', description)
                            
                        # Break when done
                        break

                # Walk through the trace entries and compile a string
                trace = '\nTrace:\n'
                unified_node_pool = root.findall("ns:UnifiedNodePool/ns:Node", namespace)
                
                for i, entry in enumerate(events, start=1):
                    t_path = ''
                    t_line = ''
                    
                    if entry == '...':
                        trace += "...\n"
                        continue
                    
                    # If it is a NodeRef, perform a search for a node with the matching ID
                    node_ref = entry.find('./ns:NodeRef', namespace)
                    if node_ref is not None:
                        if len(unified_node_pool) > 0:
                            ref_id = node_ref.get('id')
                            for pool_node in unified_node_pool:
                                if ref_id == pool_node.get('id'):
                                    # Ref ID matched with node in UnifiedNodePool
                                    srcLocation = pool_node.find('./ns:SourceLocation', namespace)
                                    t_path = srcLocation.get('path')
                                    t_line = srcLocation.get('line')
                        else:
                            err_count += 1
                            logger.error("Vulnerability {} (Rule ID: {}): Cannot resolve NodeRef ID {} in UnifiedNodePool".format(vulnerability_num, rule_id, node_ref.get('id')))
                    # No NodeRef tag means it is a main node
                    else:
                        srcLocation = entry.find("./ns:Node/ns:SourceLocation", namespace)
                        if srcLocation is None: continue
                        t_path = srcLocation.get('path')
                        t_line = srcLocation.get('line')
                    
                    t_path = os.path.join(source_base_path, t_path) if len(t_path) > 0 and len(source_base_path) > 0 else t_path
                    t_path = t_path.replace(substr, "", 1)
                    t_path = os.path.join(prepend, t_path).replace('\\', '/')
                    trace += f"{i}) {t_path}:{t_line}\n" if len(t_path) + len(t_line) > 0 else f"{i})\n"
                # End of trace loop
                
                # On the last entry, add the fact information
                facts_info = last_entry_info.findall("./ns:Node/ns:Knowledge/ns:Fact", namespace)
                if facts_info is not None and len(facts_info) > 0:
                    trace += "Facts:\n"
                    for i, fact in enumerate(facts_info, start=1):
                        trace += f"{i}) {fact.text}\n"
                
                trace = trace.strip()

                # Map rule ID to CWE
                cwe = ''
                raw_cwe = ''
                for rule in root.findall('.//ns:Rule', namespace):
                    if rule.get('id') == rule_id:
                        raw_cwe = rule.find('.//ns:Group[@name="altcategoryCWE"]', namespace).text
                        # Going to stick with the first cwe entry even though there are multiple in the file
                        cwe = raw_cwe.split(',')[0].replace('CWE ID ', '')
                        break
                
                # Get tool cwe before any overrides are performed
                if len(raw_cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(raw_cwe.replace('CWE ID ', '')) if raw_cwe.replace('CWE ID ', '').isdigit() else raw_cwe.replace('CWE ID ', '')
                
                # If the type is a Memory Leak, change the line number to the one defined by replacement definition "FirstTraceLocation.line"
                if vulnerability_type == 'Memory Leak':
                    line = replacement_defs['FirstTraceLocation.line']
                
                # Perform cwe overrides if user requests
                cwe, confidence = cwe_conf_override(control_flags, override_name=vulnerability_type, cwe=cwe, override_scanner=current_parser)
                
                # Check if cwe is in categories dict
                if control_flags[FLAG_VULN_MAPPING] and len(cwe) > 0 and cwe in cwe_categories.keys():
                    cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
                else:
                    cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                
                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path = os.path.join(source_base_path, file_path) if len(source_base_path) > 0 else file_path
                path = path.replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                
                line = int(line) if str(line).isdigit() else line
                
                # Resolve language of the file
                lang = resolve_lang(os.path.splitext(path)[1])
                
                # Generate ID for Fortify finding
                preimage = f"{path}{line}{vulnerability_type}{description}"
                id = idgenerator.hash(preimage)
                #id = "FORT{:04}".format(finding_count+1)

                # Write row to outfile
                parser_writer.write_row({'CWE':cwe_cat,
                                    'Confidence':confidence,
                                    'Maturity':'Proof of Concept',
                                    'Mitigation':'None',
                                    'Mitigation Comment':'',
                                    'Comment':'',
                                    'ID':id,
                                    'Type':vulnerability_type,
                                    'Path':path,
                                    'Line':line,
                                    'Symbol':trace,
                                    'Message':description,
                                    'Tool CWE':tool_cwe,
                                    'Tool':analyzer,
                                    'Scanner':scanner,
                                    'Language':lang,
                                    'Severity':severity
                                })
                
                finding_count += 1
            
            except Exception:
                logger.error(f"Vulnerability {vulnerability_num} (Rule ID: {rule_id}) of \'{fpath}\': {traceback.format_exc()}")
                err_count += 1

    logger.info(f"Successfully processed {finding_count} vulnerabilities")
    logger.info(f"Number of erroneous vulnerabilities: {err_count}")
    if err_count > 0:
        logger.warning("Errors have been detected while parsing a Fortify .fpr file. To troubleshoot, unzip the .fpr file and manually search the \"audit.fvdl\" file for the problematic vulnerabilities.")
    return err_count
# End of parse


def check_fvdl(fpath):
    # Create a temporary directory to extract files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Extract the FPR archive
        with zipfile.ZipFile(fpath, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        # Locate the audit.fvdl file
        fvdl_path = os.path.join(temp_dir, "audit.fvdl")
        if not os.path.exists(fvdl_path):
            return False
        else: return True