# cppcheck.py
import os
import logging
import traceback
import html
from csv import DictWriter
import xml.etree.ElementTree as ET
from . import FLAG_CATEGORY_MAPPING, cwe_categories
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE, progress_bar
from .parser_tools.user_overrides import cwe_conf_override

logger = logging.getLogger(__name__)
config_errors = ['templateRecursion', 'checkLevelNormal', 'checkersReport', 'missingInclude', 'missingIncludeSystem', 'toomanyconfigs', 'ConfigurationNotChecked', 'normalCheckLevelMaxBranches']

def path_preview(fpath):
    # Parse the XML file
    try:
        tree = ET.parse(fpath)
        root = tree.getroot()
        errors = root.find('errors')
        for error in errors.findall('error'):
            location = error.find('location')
            if location is not None:
                return html.unescape(location.get('file', '[ERROR] Key error: \'location\''))
        return '[ERROR] No paths found'
    except Exception as e:
        return f"[ERROR] {e}"

def parse(fpath, scanner, substr, prepend, control_flags):
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Count errors encountered while running
    err_count = 0
    
    # Parse the XML file
    tree = ET.parse(fpath)
    root = tree.getroot()
    errors = root.find('errors')
    
    # Check if there are entries to read
    total_entries = len(errors.findall('error'))
    if total_entries <= 0:
        logger.error("No entries found in the XML file. Skipping cppcheck parsing.")
        return err_count + 1
    
    scanner_version = root.find('cppcheck').get('version')
    scanner = f"CppCheck {scanner_version}"
    
    # Keep track of error number for debug
    error_num = 0
    finding_count = 0
    total_errors = len(errors.findall('error'))
    
    # Output filtered CppCheck findings here
    from . import LOGS_DIR
    with open(os.path.join(LOGS_DIR, '{}_config_errors.csv'.format(scanner.replace(' ', '_'))), 'w', newline='', encoding='utf-8-sig') as config_out_fp:
        config_out = DictWriter(config_out_fp, fieldnames=['ID','Severity','Message','Verbose'])
        config_out.writeheader()
    
    
        # Iterate through the 'error' elements in the XML
        for error in errors.findall('error'):
            try:
                error_num += 1
                progress_bar(error_num, total_errors, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
                
                if error.get('id') in config_errors:
                    # Config error found. The error will be output to a separate CSV
                    id = error.get('id', '')
                    severity = error.get('severity', '')
                    msg = html.unescape(error.get('msg', ''))
                    verbose = html.unescape(error.get('verbose', ''))
                    config_out.writerow({"ID": id, "Severity": severity, "Message": msg, "Verbose": verbose})
                    continue
                    
                cwe = error.get('cwe', '')
                category = error.get('id', '')
                severity = error.get('severity', '')
                message = html.unescape(error.get('msg', ''))
                location = error.find('location')
                file = html.unescape(location.get('file', ''))
                line = location.get('line', '')
                symbol = error.find('symbol')
                symbol = symbol.text if symbol is not None else ''
                
            except:
                logger.error(f"Erroneous entry: {html.unescape(ET.tostring(error, encoding='utf8').decode('utf8'))}\n"
                             + traceback.format_exc())
                err_count += 1
                continue
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Check if category is from one of the two python addons (mandatory override)
            if 'y2038' in category:
                cwe = '190'
            elif 'threadsafety' in category:
                cwe = '362'
            
            # Perform cwe overrides if user requests
            cwe, confidence = cwe_conf_override(control_flags, override_name=category, cwe=cwe, message_content=message, override_scanner=current_parser)
            
            # Check if cwe is in categories dict
            if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
            else:
                cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                    
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = str(file).replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')
            
            line = int(line) if str(line).isdigit() else line
            
            # Generate ID for Coverity finding (concat Path, Line, Scanner, and Message)
            preimage = f"{path}{line}{message}{tool_cwe}"
            id = idgenerator.hash(preimage)
            #id = "CPP{:04}".format(finding_count+1)

            # Write row to outfile
            parser_writer.write_row({'CWE':cwe_cat,
                                'Confidence':confidence,
                                'Maturity':'Proof of Concept',
                                'Mitigation':'None',
                                'Mitigation Comment':'',
                                'Comment':'',
                                'ID':id,
                                'Type':category,
                                'Path':path,
                                'Line':line,
                                'Symbol':symbol,
                                'Message':message,
                                'Tool CWE':tool_cwe,
                                'Tool':'',
                                'Scanner':scanner,
                                'Language':'c/c++',
                                'Severity':severity
                            })
            finding_count += 1
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous entries: {err_count}")
    return err_count
# End of parse
