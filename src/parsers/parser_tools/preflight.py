# preflight.py

# Handles loading, dumping, and application of preflight rules

import os
import json
import logging
from .prule import PRule
import parsers


logger = logging.getLogger(__name__)

def load_prules():
    from parsers import CONFIG_DIR
    
    prules = []
    data_path = os.path.join(CONFIG_DIR, 'preflight_rules.json')
    
    if not os.path.isfile(data_path):
        logger.warning("Unable to load preflight rules: 'preflight_rules.json' does not exist. Loading default list instead.")
        data_path = os.path.join(CONFIG_DIR, 'default_preflight_rules.json')
        if not os.path.isfile(data_path):
            return "Unable to load default preflight rules: 'default_preflight_rules.json' does not exist. Continuing with preflight rules disabled."
    
    with open(data_path, 'r') as r:
        prule_data = json.load(r)
    
    for pr in prule_data['PRules']:
        prules.append(PRule.from_dict(pr))
    
    prules.sort(key=lambda rule: int(rule.precedence))

    logger.info("Preflight rules loaded successfully")
    return prules


def save_prules():
    from parsers import CONFIG_DIR
    
    data_path = os.path.join(CONFIG_DIR, 'preflight_rules.json')
    
    out = {'Preflight Rules': []}
    
    parsers.prules.sort(key=lambda rule: int(rule.precedence))
    
    for pr in parsers.prules:
        out['Preflight Rules'].append(pr.to_dict())
    
    with open(data_path, 'w') as w:
        json.dump(out, w, indent=4)
    
    logger.info(f"Preflight rules saved to '{data_path}'")


def apply_prules(data):
    for row in data:
        for pr in parsers.prules:
            # Returns None if row does not match a rule
            if replacement := pr.apply_rule(row):
                # Update row fieldnames defined in the rule's replacement dict
                for fieldname in replacement.keys():
                    row[fieldname] = replacement[fieldname]
