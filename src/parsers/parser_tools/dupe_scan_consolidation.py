# dupe_scan_consolidation.py

import re
import logging
import parsers
from .toolbox import Fieldnames, InputConfigFlags
from .progressbar import progress_bar,SPACE

logger = logging.getLogger(__name__)

def _fix_scanner_name(scanner):
    if match := re.match(r"^(.*?)\s+v?\d+(?:\.\d+)*$", scanner):
        return match.group(1).lower()
    else:
        return scanner.lower()

def dupe_scan_consolidation(data):
    from .parser_writer import search_row, update_row
    
    if not parsers.control_flags[parsers.FLAG_DUPE_SCAN_CONSOLIDATION]:
        return -1
    
    # Perform dupe searching
    dupe_count = 0
    for i, row in enumerate(data, start=1):
        progress_bar(i, len(data), prefix=InputConfigFlags.DUPE_SCAN_CONSOLIDATION.flag.rjust(SPACE))
        
        # Check to see if this is already a duplicate row or if it is designated as a canon row
        if (row[Fieldnames.CONFIDENCE.value].lower() == Fieldnames.DUPLICATE_CONF.value.lower()):
            continue
        
        # Check to see if the row exists
        matches = search_row([(Fieldnames.TYPE.value, row[Fieldnames.TYPE.value], True),
                            (Fieldnames.SCANNER.value, _fix_scanner_name(row[Fieldnames.SCANNER.value]), False),
                            (Fieldnames.PATH.value, row[Fieldnames.PATH.value], True),
                            (Fieldnames.LINE.value, row[Fieldnames.LINE.value], True)
                        ],
                        skip_ids=row[Fieldnames.ID.value])
        for m in matches:
            # Replace all matches with the current row's data
            _end = f". {row[Fieldnames.VALIDATOR_COMMENT.value]}" if len(row[Fieldnames.VALIDATOR_COMMENT.value]) > 0 else row[Fieldnames.VALIDATOR_COMMENT.value]
            validator_comment_replacement = f"This finding is a duplicate of a {row[Fieldnames.SCANNER.value]} finding with the same ID" + _end
            try:
                update_row(m[Fieldnames.ID.value],
                            updates={
                                Fieldnames.SCORING_BASIS.value: row[Fieldnames.SCORING_BASIS.value],
                                Fieldnames.CONFIDENCE.value: Fieldnames.DUPLICATE_CONF.value,
                                Fieldnames.MATURITY.value : row[Fieldnames.MATURITY.value],
                                Fieldnames.MITIGATION.value: row[Fieldnames.MITIGATION.value],
                                Fieldnames.ID.value: row[Fieldnames.ID.value],
                                Fieldnames.VALIDATOR_COMMENT.value: validator_comment_replacement
                            },
                            skip_ids=row[Fieldnames.ID.value])
            except ValueError:
                continue
        dupe_count += len(matches)
    logger.info(f"Discovered {dupe_count} duplicate findings")
    return dupe_count
