# flawfinder.py

import os
import csv
import logging
import traceback
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE,progress_bar
from .parser_tools.toolbox import Fieldnames
from .parser_tools.language_resolver import resolve_lang_from_ext

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Parse the input file
    try:
        with open(fpath, "r", encoding='utf-8-sig') as read_obj:
            csv_reader = csv.DictReader(read_obj)
            first_row = next(csv_reader)
            cell_preview = first_row['File']
            return cell_preview
    except Exception as e:
        return f"[ERROR] {e}"

def parse(fpath, scanner, substr, prepend):
    logger.info("Parsing %s - %s", scanner, fpath)
    
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
            
                cwe = row['CWEs']
                if cwe is not None and isinstance(cwe, str):
                    cwe = cwe.replace('CWE-', '')
                else:
                    cwe = ''
                
                # Get tool cwe before any overrides are performed
                if len(cwe) <= 0:
                    tool_cwe = '(blank)'
                else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
                
                # CWEs are either a single entry or multiple that are comma-separated. Use the first entry.
                if len(cwe) > 0:
                    cwe = cwe.split(',')[0]
                    # Some CWEs have a slash in them, and according to documentation it is in "more-general/more-specific" format
                    # The '!' is used to denote which CWE is the one the finding mapped to. Since we only care about more-specific, we will ignore '!'
                    cwe = cwe.split('/')[-1].replace('!', '')
                
                # Cut and prepend the paths and convert all backslashes to forwardslashes
                path = str(row['File']).replace(substr, "", 1)
                path = os.path.join(prepend, path).replace('\\', '/')
                
                line = int(row['Line']) if str(row['Line']).isdigit() else row['Line']
                
                # Severity level
                severity = row['Level']
                if severity is not None:
                    # Documentation designates 0 as "very little risk" and 5 as "great risk"
                    try:
                        match str(severity):
                            case '0':
                                severity = f"{severity} (Very Little Risk)"
                            case '1':
                                severity = f"{severity} (Little Risk)"
                            case '2':
                                severity = f"{severity} (Medium Risk)"
                            case '3':
                                severity = f"{severity} (High Risk)"
                            case '4':
                                severity = f"{severity} (Very High Risk)"
                            case '5':
                                severity = f"{severity} (Great Risk)"
                            case _:
                                pass
                    except ValueError:
                        pass
                
                # Type
                category = row['Category']
                
                # Symbol
                symbol = row['Context']
                if not (symbol is not None and isinstance(symbol, str) and len(symbol) > 0):
                    symbol = row['Name']
                
                # Language
                lang = resolve_lang_from_ext(os.path.splitext(path)[1])
                
                # Message
                warning = row['Warning']
                suggestion = row['Suggestion']
                note = row['Note']
                message = ". ".join(part for part in [warning, suggestion, note] if len(part.strip()) > 0)
                
                # Generate ID for finding if fingerprint is not here
                fingerprint = row['Fingerprint']
                if not (fingerprint is not None and isinstance(fingerprint, str) and len(fingerprint) > 0):
                    preimage = '\0'.join(str(p) for p in (path, line, category, message) if len(str(p)) > 0)
                    fingerprint = idgenerator.hash(preimage)

                # Write row to outfile
                parser_writer.write_row({Fieldnames.SCORING_BASIS.value:cwe,
                                    Fieldnames.CONFIDENCE.value:Fieldnames.DEFAULT_CONF.value,
                                    Fieldnames.MATURITY.value:Fieldnames.DEFAULT_MATURITY.value,
                                    Fieldnames.MITIGATION.value:Fieldnames.DEFAULT_MITIGATION.value,
                                    Fieldnames.PROPOSED_MITIGATION.value:'',
                                    Fieldnames.VALIDATOR_COMMENT.value:'',
                                    Fieldnames.ID.value:fingerprint,
                                    Fieldnames.TYPE.value:category,
                                    Fieldnames.PATH.value:path,
                                    Fieldnames.LINE.value:line,
                                    Fieldnames.SYMBOL.value:symbol,
                                    Fieldnames.MESSAGE.value:message,
                                    Fieldnames.TRACE.value:'',
                                    Fieldnames.TOOL_CWE.value:tool_cwe,
                                    Fieldnames.TOOL.value:'',
                                    Fieldnames.SCANNER.value:scanner,
                                    Fieldnames.LANGUAGE.value:lang,
                                    Fieldnames.SEVERITY.value:severity
                                })
                finding_count += 1
            except Exception:
                logger.error("Row %d of \'%s\': %s", row_num, fpath, traceback.format_exc())
                err_count += 1
    logger.info("Successfully processed %d findings", finding_count)
    logger.info("Number of erroneous rows: %d", err_count)
    return finding_count, err_count
# End of parse
