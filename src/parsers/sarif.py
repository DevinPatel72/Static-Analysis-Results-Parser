# sarif.py

import os
import re
import logging
import traceback
import json
import parsers
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames, Scanners, select_scanner, console


logger = logging.getLogger(__name__)

# Remaps all known severity values to keywords supported by SARIF standard
def _severity_remap(severity, scanner_type, default=''):
    return scanner_type.severity_map.get(str(severity).lower(), default)

def path_preview(fpath):
    # TODO No preview available for now
    return 'No preview available for SARIF'

def _fetch_fingerprint(result):
    finding_id = ''
    fingerprints = result.get('fingerprints', {})
    if len(fingerprints) > 0:
        finding_id = fingerprints.get('findingId', '')
        if len(finding_id) <= 0:
            _, finding_id = next(iter(fingerprints.items()), ('', ''))
    
    if len(finding_id) > 0:
        return finding_id

    fingerprints = result.get('partialFingerprints', {})
    if len(fingerprints) > 0:
        finding_id = fingerprints.get('findingId', '')
        if len(finding_id) <= 0:
            _, finding_id = next(iter(fingerprints.items()), ('', ''))
    
    return finding_id
    

def parse(fpath, scanner, substr, prepend):
    # Convert SARIF file to dict rows
    result_num = 0
    total_results = 0
    finding_count = 0
    err_count = 0
    
    # Open json in read
    try:
        with open(fpath, mode='r', encoding='utf-8-sig') as f:
            data = json.load(f)
    except:
        logger.error(f"File \'{fpath}\' failed to open:\n{traceback.format_exc()}")
        return finding_count, err_count + 1
    
    total_results = sum([len(run.get('results', [])) for run in data.get('runs', [])])
    
    # Each run is a scanner
    for run in data.get('runs', []):
        # Get scanner info
        t_scanner = run['tool']['driver']['name']
        
        # Iterate through results and rebuild excel column
        for result in run.get('results', []):
            result_num += 1
            progress_bar(result_num, total_results, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
            try:
                finding_id = _fetch_fingerprint(result)
                new_row = {
                    Fieldnames.SCANNER.value: t_scanner,
                    Fieldnames.ID.value: finding_id
                }
                
                # Load all properties
                properties = result.get('properties', {})
                if len(properties) > 0:
                    if "cve" in properties:
                        new_row[Fieldnames.SCORING_BASIS.value] = properties["cve"]
                    elif "cwe" in properties:
                        new_row[Fieldnames.SCORING_BASIS.value] = properties["cwe"]
                        
                    field_lookup = {f.lower().replace(" ", "_"): f for f in Fieldnames.HEADERS.value}

                    for prop, val in properties.items():
                        if prop in field_lookup:
                            new_row[field_lookup[prop]] = val
                        else:
                            new_row[prop] = val

                # Get path and line
                try:
                    path = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
                    line = result['locations'][0]['physicalLocation']['region']['startLine']
                    
                    # Cut and prepend the paths and convert all backslashes to forward slashes
                    path = path.replace(substr, "", 1)
                    path = os.path.join(prepend, path).replace('\\', '/')
                except (KeyError, IndexError):
                    path = ''
                    line = ''
                
                new_row[Fieldnames.PATH.value] = path
                new_row[Fieldnames.LINE.value] = line

                # Type
                new_row[Fieldnames.TYPE.value] = result.get('ruleId', '')

                # Message
                new_row[Fieldnames.MESSAGE.value] = result.get('message', {}).get('text', '')
                
                # Severity
                new_row[Fieldnames.SEVERITY.value] = result.get('level', '')

                # Trace
                trace = ''
                codeflows = result.get('codeFlows', {})
                if len(codeflows) > 0:
                    try:
                        # Each location is a trace entry
                        locations = codeflows[0]['threadFlows'][0]['locations']
                        for i, location in enumerate(locations, start=1):
                            t_path = ''
                            t_line = ''
                            t_msg = ''
                            
                            # Get trace message
                            try:
                                t_msg = location['location']['message']['text']
                            except (KeyError, IndexError):
                                t_msg = ''
                            
                            # Get trace path
                            try:
                                t_path = location['location']['physicalLocation']['artifactLocation']['uri']
                                if len(t_path) > 0:
                                    # Cut and prepend the paths and convert all backslashes to forward slashes
                                    t_path = t_path.replace(substr, "", 1)
                                    t_path = os.path.join(prepend, t_path).replace('\\', '/')
                            except (KeyError, IndexError):
                                t_path = ''
                            
                            # Get trace line
                            try:
                                t_line = location['location']['physicalLocation']['region']['startLine']
                            except (KeyError, IndexError):
                                t_line = ''
                            
                            parts = [t_path, t_line, t_msg]
                            trace += f"{i}) {':'.join(str(p) for p in parts if len(str(p)) > 0)}\n"
                    except (KeyError, IndexError):
                        trace = ''
                        
                new_row[Fieldnames.TRACE.value] = trace.strip()
                
                # Final check to fill in empty headers
                if Fieldnames.CONFIDENCE.value not in new_row.keys():
                    new_row[Fieldnames.CONFIDENCE.value] = Fieldnames.DEFAULT_CONF.value
                if Fieldnames.MATURITY.value not in new_row.keys():
                    new_row[Fieldnames.MATURITY.value] = Fieldnames.DEFAULT_MATURITY.value
                if Fieldnames.MITIGATION.value not in new_row.keys():
                    new_row[Fieldnames.MITIGATION.value] = Fieldnames.DEFAULT_MITIGATION.value
                    
                for fieldname in Fieldnames.HEADERS.value:
                    if fieldname not in new_row.keys():
                        new_row[fieldname] = ''
            
                # Write row to outfile
                parser_writer.write_row(new_row)
                finding_count += 1
            except:
                logger.error(f"Result ID {finding_id} of \'{fpath}\':\n{traceback.format_exc()}")
                err_count += 1
    return finding_count, err_count
    
# Converts list of dictionaries to SARIF format
def rows_to_sarif(data):
    # Get list of scanners
    runs = {}
    
    # Prep the results and rules
    for row in data:
        scanner = row[Fieldnames.SCANNER.value]
        selected_scanner = select_scanner(scanner)
        if selected_scanner == Scanners.SRM:
            selected_scanner = select_scanner(row[Fieldnames.TOOL.value])
        
        if scanner not in runs:
            runs[scanner] = {
                "tool": {
                    "driver": {
                        "name": scanner,
                        "rules": []
                    }
                },
                "results": [],
                "_rules": {}
            }
        
        run = runs[scanner]
        
        # Get rule
        rule_id = row[Fieldnames.TYPE.value]
        if rule_id not in run['_rules']:
            rule = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": rule_id
                }
            }
            run['_rules'][rule_id] = rule
            run["tool"]["driver"]["rules"].append(rule)

        # Get result
        result = {
            "ruleId": rule_id,
            "message": {
                "text": row[Fieldnames.MESSAGE.value]
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": row[Fieldnames.PATH.value]
                    },
                    "region": {
                        "startLine": row[Fieldnames.LINE.value]
                    }
                }
            }],
            "fingerprints": {
                "findingId": row[Fieldnames.ID.value]
            },
            "properties": {
                Fieldnames.LANGUAGE.value.lower().replace(' ', '_'): row[Fieldnames.LANGUAGE.value],
                Fieldnames.SYMBOL.value.lower().replace(' ', '_'): row[Fieldnames.SYMBOL.value],
                Fieldnames.SEVERITY.value.lower().replace(' ', '_'): row[Fieldnames.SEVERITY.value]
            } | ({
                Fieldnames.CONFIDENCE.value.lower(): row[Fieldnames.CONFIDENCE.value],
                Fieldnames.MATURITY.value.lower().replace(' ', '_'): row[Fieldnames.MATURITY.value],
                Fieldnames.MITIGATION.value.lower().replace(' ', '_'): row[Fieldnames.MITIGATION.value],
                Fieldnames.PROPOSED_MITIGATION.value.lower().replace(' ', '_'): row[Fieldnames.PROPOSED_MITIGATION.value],
                Fieldnames.VALIDATOR_COMMENT.value.lower().replace(' ', '_'): row[Fieldnames.VALIDATOR_COMMENT.value]
            } if parsers.control_flags[parsers.FLAG_SARIF_STITCH_PROPERTIES] else {}) 
        }
        
        severity = _severity_remap(row[Fieldnames.SEVERITY.value], selected_scanner)
        if len(severity) > 0:
            result['level'] = severity
        
        # Trace
        if len(row[Fieldnames.TRACE.value]) > 0:
            trace = row[Fieldnames.TRACE.value].strip().split('\n')
            locations = []
            for t in trace:
                t = t.strip()
                if len(t) <= 0:
                    continue
                
                # Extract path, line, and message from trace entry
                if (m := re.match(r"^\d+\) (.*?):(\d+)(?::(.*))?$", t)):
                    path = m.group(1)
                    line = int(m.group(2))
                    msg = m.group(3) if m.group(3) is not None else ""
                else:
                    path = line = msg = ""
                
                # Creation location object
                location = {}

                if len(msg) > 0:
                    location["message"] = {"text": msg.strip()}

                if len(path) > 0:
                    location["physicalLocation"] = {
                        "artifactLocation": {
                            "uri": path
                        }
                    }

                    if isinstance(line, int) or len(line) > 0:
                        location["physicalLocation"]["region"] = {
                            "startLine": int(line) if str(line).isdigit() else line
                        }

                locations.append({
                    "location": location
                })
            
            if len(locations) > 0:
                result["codeFlows"] = [{
                    "threadFlows": [{
                        "locations": locations
                    }]
                }]
        
        # Scanner-specific properties
        if selected_scanner in [Scanners.DEP_CHECK, Scanners.NVD_CVE]:
            result['properties']['cve'] = row[Fieldnames.SCORING_BASIS.value]
            result['properties']['tool_cwe'] = row[Fieldnames.TOOL_CWE.value]
        # Remaining scanners
        else:
            result['properties']['cwe'] = row[Fieldnames.SCORING_BASIS.value]
            result['properties']['tool_cwe'] = row[Fieldnames.TOOL_CWE.value]

        run["results"].append(result)

    for run in runs.values():
        del run['_rules']

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": list(runs.values())
    }
    
    return sarif
    
