# spotbugs.py

import os
import logging
import json
import re
import traceback
import xml.etree.ElementTree as ET
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames, console

logger = logging.getLogger(__name__)

spotbugs_bug_patterns = {}

def path_preview(fpath):
    # Parse the input file
    try:
        if fpath.endswith('.xml'):
            tree = ET.parse(fpath)
            root = tree.getroot()
            for instance in root.findall('BugInstance'):
                source_line = None
                if (t_source_line := instance.find('SourceLine')) is not None:
                    source_line = t_source_line
                elif (method := instance.find('Method')) is not None:
                    source_line = method.find('SourceLine')
                elif (classname := instance.find('Class')) is not None:
                    source_line = classname.find('SourceLine')
                
                if source_line is not None:
                    if (preview := source_line.get('sourcepath', None)) is not None:
                        return _normalize_text(preview) # There may be empty space characters

            return '[ERROR] No paths found'
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
    
    if fpath.endswith('.xml'):
        finding_count, err_count = _parse_xml(fpath, scanner, substr, prepend)
    else:
        finding_count, err_count = _parse_sarif(fpath, scanner, substr, prepend)
    
    
    logger.info("Successfully processed %d findings", finding_count)
    logger.info("Number of erroneous rows: %d", err_count)
    return finding_count, err_count
# End of parse

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
    for rule in data['tool']['driver']['rules']:
        rule_id = rule['id']
        short_desc = _normalize_text(rule['shortDescription']['text'])
        long_desc = _normalize_text(rule['messageStrings']['default']['text'])
        details = _normalize_text(rule['fullDescription']['text']).replace('\n', '')
        
        append_cwe = {}
    
        for relationship in rule.get('relationships', []):
            if 'cwe' in relationship['target']['toolComponent']['name'].lower().strip():
                append_cwe['cweid'] = relationship['target']['id']
                break
        
        insert_pattern(rule_id, append_cwe | {"ShortDescription": short_desc, "LongDescription": long_desc, "Details": details})
    
    # Iterate through results
    for result in data['results']:
        try:
            result_num += 1
            progress_bar(result_num, total_results, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
        
            # Type
            bug_type = result['ruleId']
        
            # Get CWE and message
            arguments = result['message'].get('arguments', [])
            cwe, message = get_spotbugs_bug_description(*arguments, bug_type=bug_type, default=('', ''))
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else:
                tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = str(result['locations'][0]['physicalLocation']['artifactLocation']['uri']).replace(substr, "", 1)
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
                    line = ''
                    endline = ''
            
            # Language
            lang = 'java'
            
            # Symbol
            logicalLocation = result['locations'][0]['logicalLocations'][0]
            symbol = logicalLocation.get('fullyQualifiedName', logicalLocation.get('name', ''))
            
            # Severity
            severity = result['level']
            
            # Possible trace if startline != endline
            if line != endline:
                trace = f"1) {path}:{line}\n2) {path}:{endline}"
            else:
                trace = ""
            
            # Generate ID
            preimage = '\0'.join(str(p) for p in (path, line, bug_type, message) if len(str(p)) > 0)
            id = idgenerator.hash(preimage)

            # Write row to outfile
            parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                                Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                                Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                                Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                                Fieldnames.PROPOSED_MITIGATION.value:'',
                                Fieldnames.VALIDATOR_COMMENT.value:'',
                                Fieldnames.ID.value:id,
                                Fieldnames.TYPE.value:bug_type,
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
            logger.error("Result with ID \"%s\", message %s in \'%s\': %s", bug_type, result.get('message', ''), fpath, traceback.format_exc())
            err_count += 1
        
    return finding_count, err_count
# End of _parse_sarif


def _parse_xml(fpath, scanner, substr, prepend):
    
    # Counters
    instance_num = 0
    finding_count = 0
    err_count = 0
    
    # Parse the XML file
    tree = ET.parse(fpath)
    root = tree.getroot()
    instances = root.findall('BugInstance')
    
    # Check if there are entries to read
    total_instances = len(instances)
    if total_instances <= 0:
        logger.warning("No entries found in the XML file. Skipping %s parsing.", scanner)
        return 0, 0
    
    scanner_version = root.get('version', '')
    scanner = f"Spotbugs {scanner_version}" if len(scanner_version) > 0 else scanner
    
    for instance in instances:
        try:
            instance_num += 1
            progress_bar(instance_num, total_instances, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
            
            # Type
            bug_type = instance.get('type')
            
            # Severity
            rank = int(instance.get('rank')) if str(instance.get('rank')).isdigit() else rank
            
            # Rank is between 1-20; 1 to 4 are scariest, 5 to 9 scary, 10 to 14 troubling, and 15 to 20 of concern bugs
            if 1 <= rank <= 4: severity = 'Scariest'
            elif 5 <= rank <= 9: severity = 'Scary'
            elif 10 <= rank <= 14: severity = 'Troubling'
            elif 15 <= rank <= 20: severity = 'Of Concern'
            else: severity = rank
            
            # So far, CWE mappings for base Spotbugs must be done manually
            cwe, message = get_spotbugs_bug_description(bug_type=bug_type, default=('','', ''))
            
            # Path, Line, and Symbol
            source_line = None
            if (t_source_line := instance.find('SourceLine')) is not None:
                source_line = t_source_line
            elif (method := instance.find('Method')) is not None:
                source_line = method.find('SourceLine')
            elif (classname := instance.find('Class')) is not None:
                source_line = classname.find('SourceLine')
            
            if source_line is not None:
                path = source_line.get('sourcepath', '')
                line = source_line.get('start', '')
                endline = source_line.get('end', '')
                symbol = source_line.get('classname', '')
            else:
                path = ''
                line = ''
                endline = line
                symbol = ''

        except:
            logger.error("Erroneous entry: %s\n%s", ET.tostring(instance, encoding='utf8').decode('utf8'), traceback.format_exc())
            err_count += 1
            continue
        
        # Get tool cwe before any overrides are performed
        if len(cwe) <= 0:
            tool_cwe = '(blank)'
        else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
        # Cut and prepend the paths and convert all backslashes to forwardslashes
        path = str(path).replace(substr, "", 1)
        path = os.path.join(prepend, path).replace('\\', '/')
        
        line = int(line) if str(line).isdigit() else line
        endline = int(endline) if str(endline).isdigit() else endline
        
        # Possible trace if startline != endline
        if line != endline:
            trace = f"1) {path}:{line}\n2) {path}:{endline}"
        else:
            trace = ""
        
        # Generate ID
        preimage = '\0'.join(str(p) for p in (path, line, message, bug_type) if len(str(p)) > 0)
        id = idgenerator.hash(preimage)

        # Write row to outfile
        parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                            Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                            Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                            Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                            Fieldnames.PROPOSED_MITIGATION.value:'',
                            Fieldnames.VALIDATOR_COMMENT.value:'',
                            Fieldnames.ID.value:id,
                            Fieldnames.TYPE.value:bug_type,
                            Fieldnames.PATH.value:path,
                            Fieldnames.LINE.value:line,
                            Fieldnames.SYMBOL.value:symbol,
                            Fieldnames.MESSAGE.value:message,
                            Fieldnames.TRACE.value:trace,
                            Fieldnames.TOOL_CWE.value:tool_cwe,
                            Fieldnames.TOOL.value:'',
                            Fieldnames.SCANNER.value:scanner,
                            Fieldnames.LANGUAGE.value:'java',
                            Fieldnames.SEVERITY.value:severity
                        })
        finding_count += 1
    logger.info("Successfully processed %d findings", finding_count)
    logger.info("Number of erroneous entries: %d", err_count)
    return finding_count, err_count
# End of _parse_xml

def insert_pattern(rule_id, new_bug_pattern):
    global spotbugs_bug_patterns
    spotbugs_bug_patterns[rule_id] = new_bug_pattern

def load_spotbugs_bug_patterns():
    from . import PROG_NAME_ABBR, MAPPINGS_DIR
    try:
        with open(os.path.join(MAPPINGS_DIR, 'spotbugs_bug_patterns.json'), 'r', encoding='utf-8-sig') as r:
            return json.load(r)
        logger.info("Loaded Spotbugs description map")
    except (FileNotFoundError, json.JSONDecodeError):
        console(f"Unable to load Spotbugs Bug Patterns: Invalid JSON format\n{PROG_NAME_ABBR} will continue without finding descriptions.", "Config Error", type='error', orig_name=__name__)
        return {"__spotbugs_bug_patterns_error__": "Returning a dict of size 1 to ensure this function only gets called once."}
    

def get_spotbugs_bug_description(*args, bug_type, default=('', '')):
    # Maps Spotbugs bug_type to its description and parses any args with it
    global spotbugs_bug_patterns
    
    if bug_type == '__spotbugs_bug_patterns_error__':
        return default
    
    if len(spotbugs_bug_patterns) <= 0:
        spotbugs_bug_patterns = load_spotbugs_bug_patterns()
    
    if bug_type in spotbugs_bug_patterns.keys():
        # Get description
        if len(args) > 0:
            # Replace all {#} tags
            description = spotbugs_bug_patterns[bug_type]['LongDescription']
            for arg in args:
                for i, arg in enumerate(args):
                    description = description.replace(f"{{{i}}}", str(arg))
        else:
            description = spotbugs_bug_patterns[bug_type]['ShortDescription']
        
        # Get other info
        cwe = spotbugs_bug_patterns[bug_type].get('cweid', '')
        cwe = cwe if cwe is not None else ''
        details = spotbugs_bug_patterns[bug_type].get('Details', '')
        
        # Append details to the end of description
        return cwe, " ".join(p for p in [description, details] if len(p) > 0)
    else:
        return default

def _normalize_text(s):
    return (
        s.replace("\u00A0", " ")
         .replace("\u200b", "")   # zero-width space
         .replace("\u202f", " ")  # narrow no-break space
    )
