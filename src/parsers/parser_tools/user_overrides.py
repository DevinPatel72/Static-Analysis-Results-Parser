# user_overrides.py

# Specify user overrides in file "user_overrides.json"

import os
import json
import logging
from parsers import FLAG_OVERRIDE_CWE, FLAG_OVERRIDE_CONFIDENCE


logger = logging.getLogger(__name__)
overrides = None

# Load overrides upon first call
def _load_overrides():
    global overrides
    from parsers import CONFIG_DIR, GUI_MODE, EMPTY_OVERRIDES
    
    os.makedirs(CONFIG_DIR, exist_ok=True)
    overrides_path = os.path.join(CONFIG_DIR, 'user_overrides.json')
    
    # Check if overrides file exists and touch it if it doesn't
    if not os.path.isfile(overrides_path):
        if GUI_MODE:
            from .inputs_gui import message_box
            message_box("Config not found", "Unable to load user overrides.\nProgram will continue execution with stubbed override rules.\nSee logfile for more details.", "warning")
            
        logger.error("Unable to find 'user_overrides.json'. A preset file can be fetched from the original source of this script. Please ensure 'user_overrides.json' exists in the directory: {}".format(CONFIG_DIR))
        
        with open(overrides_path, 'w', encoding='utf-8-sig') as f:
            json.dump(json.loads(EMPTY_OVERRIDES), f, indent=2)
        
        
    with open(overrides_path, 'r', encoding='utf-8-sig') as r:
        overrides = json.load(r)

# Global function to handle override
def cwe_conf_override(control_flags, override_name, cwe='', confidence='To Verify', message_content='', override_scanner=''):
    if overrides is None:
        _load_overrides()
    
    # Check if override rule is defined
    if override_name not in overrides[override_scanner].keys():
        return cwe, confidence
    
    t_override = overrides[override_scanner][override_name]
    
    # Check if override is a callable
    if isinstance(t_override, str) and t_override in globals().keys() and callable((t_callable := globals()[t_override])):
        result = t_callable(message_content)
        
        if control_flags[FLAG_OVERRIDE_CWE]:
            cwe = result.get("cwe", cwe)
        
        if control_flags[FLAG_OVERRIDE_CONFIDENCE]:
            confidence = result.get("confidence", "To Verify")
        else:
            confidence = "To Verify"
    elif isinstance(t_override, dict):
        if control_flags[FLAG_OVERRIDE_CWE]:
            cwe = t_override.get("cwe", cwe)
            
        if control_flags[FLAG_OVERRIDE_CONFIDENCE]:
            confidence = t_override.get("confidence", "To Verify")
        else:
            confidence = "To Verify"
    else:
        confidence = "To Verify"
    
    return str(cwe), confidence


# Function to handle "knownConditionTrueFalse" messages for CPPCheck
def _cppcheck_known_condition_handler(msg):
    if "true" in msg.lower():
        return {"cwe": "571"}
    elif "false" in msg.lower():
        return {"cwe": "570"}
    elif "Same expression" in msg:
        return {"cwe": "561", "confidence": "Info"}
    else:
        return {"cwe": ""}

# Function to handle "array_compared_to_null" messages for CPPCheck
def _coverity_array_compared_to_null_handler(msg):
    if "true" in msg.lower():
        return {"cwe": "571"}
    elif "false" in msg.lower():
        return {"cwe": "570"}
    else:
        return {"cwe": ""}
