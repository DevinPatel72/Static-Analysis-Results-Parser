# cwe_category_mapping.py

import parsers

def check_CWE(cwe):
    if parsers.control_flags[parsers.FLAG_CATEGORY_MAPPING] and cwe in parsers.cwe_categories.keys():
        return f"{cwe}:{parsers.cwe_categories[cwe]}"
    else:
        return int(cwe) if str(cwe).isdigit() else cwe
