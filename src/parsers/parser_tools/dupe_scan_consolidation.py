# dupe_scan_consolidation.py

import re
import parsers
from .toolbox import Fieldnames, InputDictKeys
from .progressbar import progress_bar,SPACE

def _fix_scanner_name(scanner):
    if match := re.match(r"^(.*?)\s+v?\d+(?:\.\d+)*$", scanner):
        return match.group(1).lower()
    else:
        return scanner.lower()

def dupe_scan_consolidation(data):
    from .parser_writer import search_row
    
    if not parsers.control_flags[parsers.FLAG_DUPE_SCAN_CONSOLIDATION]:
        return -1
    
    # Track IDs that were already marked as duplicates so they can be skipped in the search_row function
    canon_row_ids = set()
    for i, row in enumerate(data[::-1], start=1):
        progress_bar(i, len(data), prefix=InputDictKeys.DUPE_SCAN_CONSOLIDATION.value.rjust(SPACE))
        
        # Check to see if this is already a duplicate row
        if (row[Fieldnames.CONFIDENCE.value].lower() == Fieldnames.DUPLICATE_CONF.value.lower()) or (row[Fieldnames.ID.value] in canon_row_ids):
            continue
        
        # Check to see if the row exists
        if m := search_row([(Fieldnames.TYPE.value, row[Fieldnames.TYPE.value], True),
                            (Fieldnames.SCANNER.value, _fix_scanner_name(row[Fieldnames.SCANNER.value]), False),
                            (Fieldnames.PATH.value, row[Fieldnames.PATH.value], True),
                            (Fieldnames.LINE.value, row[Fieldnames.LINE.value], True)
                        ],
                        skip_ids=(canon_row_ids | {row[Fieldnames.ID.value]})):
            row[Fieldnames.SCORING_BASIS.value] = m[Fieldnames.SCORING_BASIS.value]
            row[Fieldnames.CONFIDENCE.value] = Fieldnames.DUPLICATE_CONF.value
            row[Fieldnames.MATURITY.value] = m[Fieldnames.MATURITY.value]
            row[Fieldnames.MITIGATION.value] = m[Fieldnames.MITIGATION.value]
            row[Fieldnames.ID.value] = m[Fieldnames.ID.value]
            _end = f". {m[Fieldnames.VALIDATOR_COMMENT.value]}" if len(m[Fieldnames.VALIDATOR_COMMENT.value]) > 0 else m[Fieldnames.VALIDATOR_COMMENT.value]
            row[Fieldnames.VALIDATOR_COMMENT.value] = f"This finding is a duplicate of a {row[Fieldnames.SCANNER.value]} finding with the same ID" + _end
            # Track matched row's ID so it will be skipped in outer loop
            canon_row_ids.add(row[Fieldnames.ID.value])
    return len(canon_row_ids)
