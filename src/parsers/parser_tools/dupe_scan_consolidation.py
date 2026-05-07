# dupe_scan_consolidation.py

from .toolbox import Fieldnames, InputDictKeys
from .progressbar import progress_bar,SPACE,DISABLE_PROGRESS_BAR

def dupe_scan_consolidation(data):
    from .parser_writer import search_row
    if not DISABLE_PROGRESS_BAR: print()
    
    for i, row in enumerate(data, start=1):
        progress_bar(i, len(data), prefix=InputDictKeys.DUPE_SCAN_CONSOLIDATION.value.rjust(SPACE))
        
        # Check to see if this is already a duplicate row
        if row[Fieldnames.CONFIDENCE.value].lower() == 'duplicate':
            continue
        
        # Check to see if the row exists
        if m := search_row([(Fieldnames.TYPE.value, row[Fieldnames.TYPE.value], True),
                            (Fieldnames.SCANNER.value, row[Fieldnames.SCANNER.value].lower(), False),
                            (Fieldnames.PATH.value, row[Fieldnames.PATH.value], True),
                            (Fieldnames.LINE.value, row[Fieldnames.LINE.value], True)
                        ],
                        skip_ids=row[Fieldnames.ID.value]):
            row[Fieldnames.SCORING_BASIS.value] = m[Fieldnames.SCORING_BASIS.value]
            row[Fieldnames.CONFIDENCE.value] = 'DUPLICATE'
            row[Fieldnames.MATURITY.value] = m[Fieldnames.MATURITY.value]
            row[Fieldnames.MITIGATION.value] = m[Fieldnames.MITIGATION.value]
            row[Fieldnames.ID.value] = m[Fieldnames.ID.value]
            _end = f". {m[Fieldnames.VALIDATOR_COMMENT.value]}" if len(m[Fieldnames.VALIDATOR_COMMENT.value]) > 0 else m[Fieldnames.VALIDATOR_COMMENT.value]
            row[Fieldnames.VALIDATOR_COMMENT.value] = f"This finding is a duplicate of a {row[Fieldnames.SCANNER.value]} finding with the same ID" + _end
