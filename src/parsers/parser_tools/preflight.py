# preflight.py

# Handles loading, dumping, and application of preflight rules

import os
import json
import logging
import traceback
import importlib
from .prule import PRule
import parsers


logger = logging.getLogger(__name__)

def load_prules():
    from parsers import CONFIG_DIR
    
    prules = []
    data_path = os.path.join(CONFIG_DIR, 'preflight_rules.py')
    
    # If the py file doesn't exist
    if not os.path.isfile(data_path):
        logger.warning("Unable to load preflight rules: 'preflight_rules.json' does not exist. Loading default list instead.")
        data_path = os.path.join(CONFIG_DIR, 'default_preflight_rules.json')
        
        if not os.path.isfile(data_path):
            return "Unable to load default preflight rules: 'default_preflight_rules.json' does not exist. Continuing with preflight rules disabled."
        
        with open(data_path, 'r', encoding='utf-8-sig') as r:
            prule_data = json.load(r)
        
        for pr in prule_data['PRules']:
            prules.append(PRule.from_dict(pr))
        
        prules.sort(key=lambda rule: int(rule.precedence))
    
    # py file does exist
    try:
        spec = importlib.util.spec_from_file_location("preflight_rules", data_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        prules = module.PRULES
    except:
        logger.error(f"Failed to import PRULES from '{data_path}'")
        logger.error(traceback.format_exc())
    

    logger.info("Preflight rules loaded successfully")
    return prules


def save_prules():
    from parsers import CONFIG_DIR
    
    data_path = os.path.join(CONFIG_DIR, 'preflight_rules.json')
    
    out = {'Preflight Rules': []}
    
    parsers.prules.sort(key=lambda rule: int(rule.precedence))
    
    for pr in parsers.prules:
        out['Preflight Rules'].append(pr.to_dict())
    
    with open(data_path, 'w', encoding='utf-8-sig') as w:
        json.dump(out, w, indent=4)
    
    logger.info(f"Preflight rules saved to '{data_path}'")


def apply_prules(data):
    for row in data:
        for pr in parsers.prules:
            # Returns None if row does not match a rule
            if replacement := pr.apply_rule(row):
                # Update row fieldnames defined in the rule's replacement dict
                for fieldname in replacement.keys():
                    if isinstance(replacement[fieldname], str) and replacement[fieldname].isdigit():
                        row[fieldname] = int(replacement[fieldname])
                    else:
                        row[fieldname] = replacement[fieldname]
