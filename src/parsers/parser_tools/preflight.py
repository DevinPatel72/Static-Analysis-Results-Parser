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
        logger.warning("Unable to load preflight rules: 'preflight_rules.json' does not exist.")
    else:
        # py file does exist
        try:
            spec = importlib.util.spec_from_file_location("preflight_rules", data_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            prules = module.PRULES
            prules.sort(key=lambda rule: int(rule.precedence))
            logger.info("Preflight rules loaded successfully")
        except:
            logger.error(f"Failed to import PRULES from '{data_path}'")
            logger.error(traceback.format_exc())
            prules = []
    
    # Now load default rules
    data_path = os.path.join(CONFIG_DIR, 'default_preflight_rules.json')
    
    if not os.path.isfile(data_path):
        logger.warning("Unable to load default preflight rules: 'default_preflight_rules.json' does not exist.")
        parsers.default_prules = []
    else:
        with open(data_path, 'r', encoding='utf-8-sig') as r:
            prule_data = json.load(r)
        
        for pr in prule_data['Preflight Rules']:
            parsers.default_prules.append(PRule.from_dict(pr))
        
        parsers.default_prules.sort(key=lambda rule: int(rule.precedence))
        logger.info("Default preflight rules loaded successfully")
    
    return prules


def save_prules(prules):
    from parsers import CONFIG_DIR
    
    if len(prules) <= 0:
        return
    
    data_path = os.path.join(CONFIG_DIR, 'preflight_rules.json')
    
    out = {'Preflight Rules': []}
    
    prules.sort(key=lambda rule: int(rule.precedence))
    
    for pr in prules:
        out['Preflight Rules'].append(pr.to_dict())
    
    with open(data_path, 'w', encoding='utf-8-sig') as w:
        json.dump(out, w, indent=4)
    
    logger.info(f"Preflight rules saved to '{data_path}'")


def apply_prules(data):
    
    def loop_rules(rules):
        for pr in rules:
            # Returns None if row does not match a rule
            if replacement := pr.apply_rule(row):
                # Update row fieldnames defined in the rule's replacement dict
                for fieldname in replacement.keys():
                    if isinstance(replacement[fieldname], str) and replacement[fieldname].isdigit():
                        row[fieldname] = int(replacement[fieldname])
                    else:
                        row[fieldname] = replacement[fieldname]
    
    for row in data:
        # Default prules first
        loop_rules(parsers.default_prules)
        loop_rules(parsers.prules)
    
