# preflight.py

# Handles loading, dumping, and application of preflight rules

import os
import logging
import traceback
import importlib
from .prule import PRule
from .cwe_category_mapping import check_CWE
from .toolbox import Fieldnames
import parsers


logger = logging.getLogger(__name__)

def load_prules():
    from parsers import CONFIG_DIR
    
    prules = []
    data_path = os.path.join(CONFIG_DIR, 'preflight_rules.py')
    
    # If the py file doesn't exist
    if not os.path.isfile(data_path):
        logger.warning("Unable to load preflight rules: 'preflight_rules.py' does not exist.")
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
    data_path = os.path.join(CONFIG_DIR, 'default_preflight_rules.py')
    
    if not os.path.isfile(data_path):
        logger.warning("Unable to load default preflight rules: 'default_preflight_rules.py' does not exist.")
        parsers.default_prules = []
    else:
        try:
            spec = importlib.util.spec_from_file_location("default_preflight_rules", data_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            parsers.default_prules = module.DEFAULT_PRULES
            prules.sort(key=lambda rule: int(rule.precedence))
            logger.info("Default preflight rules loaded successfully")
        except:
            logger.error(f"Failed to import DEFAULT_PRULES from '{data_path}'")
            logger.error(traceback.format_exc())
            parsers.default_prules
    
    return prules


def save_prules(prules):
    from parsers import CONFIG_DIR
    
    if len(prules) <= 0:
        return
    
    data_path = os.path.join(CONFIG_DIR, 'preflight_rules.py')
    
    prules.sort(key=lambda rule: int(rule.precedence))
    
    s_prules = []
    
    for pr in prules:
        rule_str = str(pr).replace("\n", "\n    ")
        s_prules.append(f"    {rule_str},\n")
    
    
    
    with open(data_path, "w", encoding="utf-8") as f:

        f.write(HEADER)

        for pr in prules:
            rule_str = str(pr).replace("\n", "\n    ")
            f.write(f"    {rule_str},\n")

        f.write(FOOTER)
    
    logger.info(f"Preflight rules saved to '{data_path}'")


def apply_prules(data):
    
    def loop_rules(rules):
        for pr in rules:
            # Returns None if row does not match a rule
            if replacement := pr.apply_rule(row):
                # Update row fieldnames defined in the rule's replacement dict
                for fieldname in replacement.keys():
                    # Skip confidence, validator comment, and ID replacements if the finding is a Duplicate
                    if fieldname in [Fieldnames.CONFIDENCE.value, Fieldnames.VALIDATOR_COMMENT.value, Fieldnames.ID.value] and row[Fieldnames.CONFIDENCE.value].lower() == 'duplicate':
                        continue
                    # Cast to integer if possible, else just replace
                    if isinstance(replacement[fieldname], str) and replacement[fieldname].isdigit():
                        row[fieldname] = int(replacement[fieldname])
                    else:
                        row[fieldname] = replacement[fieldname]
    
    for row in data:
        # Default prules first
        loop_rules(parsers.default_prules)
        loop_rules(parsers.prules)
        
        # Check if cwe is in categories dict
        row[Fieldnames.SCORING_BASIS.value] = check_CWE(row[Fieldnames.SCORING_BASIS.value])
        
    

HEADER = '''#############################################################
# Parameter Definitions
#   PRule:
#       rule_id     (str)     : Name of the rule
#       precedence (int >= 0): Order that the rules will be applied.
#                               Highest value is last, equal value is random amongst rules of the same value.
#       condition   (RuleGroup OR Condition): Pass a Condition object if there is only 1 pattern that you want to match.
#                                             Pass a RuleGroup object if there is an expression of rules you want to match.
#       replacement (dict)    : Dictionary of Fieldname enum values mapped to the rule's replacement value
#
#   RuleGroup:
#       operator    (str) : Choose among "AND", "OR", or "NOT"
#       rules       (list): List of Condition objects
#
#   Condition:
#       fieldname   (Fieldname) : Target fieldname to match the pattern parameter to
#       pattern     (str)       : The pattern to match to the target string
#       strictness  (Strictness): Adjusts the strictness of the pattern matching. See below for Enum values.
#       case_sensitive (bool) : True for case sensitive matching, False for case insensitive matching.
#
#   Strictness:
#       EXACT (Does NOT override rule_order parameter)
#       CONTAINS
#       STARTSWITH
#       ENDSWITH
#       GLOB  (Path Globbing, e.g. /path/**/*.py)
#       REGEX (Regular Expression)
#
#
# Examples:
#       PRULES = [
#           #### This rule will match all paths with GLOB "source_dir/dir1/**/*.py"
#           PRule(
#               rule_id='example_single_condition',
#               precedence=1,
#               condition=Condition(fieldname='Path', pattern='source_dir/dir1/**/*.py', strictness=Strictness.GLOB, case_sensitive=False),
#               replacement={Fieldnames.SCORING_BASIS.value: '710', Fieldnames.CONFIDENCE.value: 'False Positive'}
#           ),
#
#           #### This rule will match (scanner contains "coverity" && type exact matches "An expression with no side-effect or unintended effect indicates a possible logic flaw")
#           PRule(
#               rule_id='example_AND_conditions',
#               precedence=2,
#               condition=RuleGroup(operator="AND", rules=[
#                        Condition(fieldname=Fieldnames.SCANNER.value, pattern=r"coverity", strictness=Strictness.CONTAINS, case_sensitive=False),
#                        Condition(fieldname=Fieldnames.TYPE.value, pattern=r"An expression with no side-effect or unintended effect indicates a possible logic flaw", strictness=Strictness.EXACT, case_sensitive=False),
#                    ]),
#               replacement={Fieldnames.SCORING_BASIS.value: '710', Fieldnames.CONFIDENCE.value: 'Info'}
#           ),
#
#           #### This rule will match ( (path contains "src" OR path contains "include") && (filename endswith ".cpp") )
#           PRule(
#               rule_id='example_NESTED_AND_OR_conditions',
#               precedence=3,
#               condition=RuleGroup("AND", [
#                     RuleGroup("OR", [
#                         Condition(Fieldnames.PATH.value, "src", Strictness.CONTAINS),
#                         Condition(Fieldnames.PATH.value, "include", Strictness.CONTAINS)
#                     ]),
#                     Condition("filename", ".cpp", Strictness.ENDSWITH)
#                 ]),
#               replacement={Fieldnames.CONFIDENCE.value: 'Info', Fieldnames.VALIDATOR_COMMENT.value: "These are all the .cpp files in paths containing 'src' or 'include'"}
#           ),
#       ]
#############################################################

from parsers.parser_tools.prule import PRule, RuleGroup, Condition, Strictness
from parsers.parser_tools.toolbox import Fieldnames

PRULES = [
'''

FOOTER = '''
]
'''
