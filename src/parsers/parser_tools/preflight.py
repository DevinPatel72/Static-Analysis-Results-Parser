# preflight.py

# Handles loading, dumping, and application of preflight rules

import os
import ast
from . import progressbar, parser_logger as logger
from .prule import PRule, ConditionGroup, Condition, Strictness
from .toolbox import Fieldnames, InputConfigFlags
import parsers

# Definitions for AST whitelisted import of a preflight rules py file
class UnsafeRuleError(ValueError):
    """Raised when a rule file contains unsupported Python syntax."""

_ALLOWED_CONSTRUCTORS = {
    'PRule': PRule,
    'ConditionGroup': ConditionGroup,
    'Condition': Condition,
}   

def load_prules(file='preflight_rules.py'):
    from parsers import PREFLIGHT_DIR

    prules = []
    data_path = os.path.join(PREFLIGHT_DIR, file)
    
    # If the py file doesn't exist
    if not os.path.isfile(data_path):
        logger.warning("Unable to load preflight rules: 'preflight_rules.py' does not exist in config/preflight directory.")
    else:
        # py file does exist
        try:
            prules = _load_prules_from_file(data_path)
            prules.sort(key=lambda rule: int(rule.precedence))
            logger.info("Preflight rules \'%s\' loaded successfully", file)
        except UnsafeRuleError as ure:
            logger.error("Failed to import PRULES from \'%s\': %s", data_path, str(ure))
            prules = []
    
    return prules


def save_prules(prules):
    from parsers import PREFLIGHT_DIR
    
    # Don't save if preflight rules were disabled
    if not parsers.control_flags[InputConfigFlags.PREFLIGHT_RULES.flag]:
        return
    
    data_path = os.path.join(PREFLIGHT_DIR, 'preflight_rules.py')
    
    prules.sort(key=lambda rule: int(rule.precedence))

    with open(data_path, "w", encoding="utf-8") as f:

        f.write(HEADER)

        for pr in prules:
            rule_str = str(pr).replace("\n", "\n    ")
            f.write(f"    {rule_str},\n")

        f.write(FOOTER)
    
    logger.info("Preflight rules saved to \'%s\'", data_path)


def apply_prules(data):
    
    # Check control flag
    if not parsers.control_flags[InputConfigFlags.PREFLIGHT_RULES.flag]:
        return
    
    # Ensure prules are sorted by precedence
    parsers.prules.sort(key=lambda rule: int(rule.precedence))
    
    def loop_rules(rules, row):
        for pr in rules:
            # Returns None if row does not match a rule
            if replacement := pr.apply_rule(row):
                # Update row fieldnames defined in the rule's replacement dict
                for fieldname in replacement.keys():
                    # Cast to integer if possible, else just replace
                    if isinstance(replacement[fieldname], str) and replacement[fieldname].isdigit():
                        row[fieldname] = int(replacement[fieldname])
                    else:
                        row[fieldname] = replacement[fieldname]
    
    for i, row in enumerate(data, start=1):
        progressbar.progress_bar(i, len(data), prefix=InputConfigFlags.PREFLIGHT_RULES.flag.rjust(progressbar.SPACE), input_id=InputConfigFlags.PREFLIGHT_RULES.flag)
        
        # Default prules first
        if parsers.control_flags[InputConfigFlags.SECURITY_PREFLIGHT_RULES.flag]:
            loop_rules(parsers.security_prules, row)
        loop_rules(parsers.prules, row)
    
    if parsers.control_flags[InputConfigFlags.SECURITY_PREFLIGHT_RULES.flag]:
        def_len = len(parsers.security_prules)
    else: def_len = 0
    logger.info("Preflight: Applied %d user rules and %d default rules", len(parsers.prules), def_len)


def _validate_node(node):
    """
    Validate an AST node against the allowed PRULES syntax.

    This function never executes the node.
    """

    # ---------------------------------------------------------------
    # Constants
    # ---------------------------------------------------------------

    if isinstance(node, ast.Constant):
        if type(node.value) not in {
            str,
            int,
            float,
            bool,
            type(None),
        }:
            raise UnsafeRuleError(
                f"Constant type '{type(node.value).__name__}' is not allowed"
            )

        return

    # ---------------------------------------------------------------
    # Lists
    # ---------------------------------------------------------------

    if isinstance(node, ast.List):
        for element in node.elts:
            _validate_node(element)

        return

    # ---------------------------------------------------------------
    # Dictionaries
    # ---------------------------------------------------------------

    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):

            # **kwargs / **dict
            if key is None:
                raise UnsafeRuleError(
                    "Dictionary unpacking is not allowed"
                )

            _validate_node(key)
            _validate_node(value)

        return

    # ---------------------------------------------------------------
    # Names
    # ---------------------------------------------------------------

    if isinstance(node, ast.Name):
        if node.id not in {'True', 'False', 'None'}:
            raise UnsafeRuleError(
                f"Name '{node.id}' is not allowed"
            )

        return

    # ---------------------------------------------------------------
    # Attribute access
    #
    # Allowed:
    #
    #     Fieldnames.PATH.value
    #     Strictness.CONTAINS
    # ---------------------------------------------------------------

    if isinstance(node, ast.Attribute):

        # Fieldnames.X.value
        if (
            node.attr == 'value'
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == 'Fieldnames'
        ):
            member_name = node.value.attr

            if not hasattr(Fieldnames, member_name):
                raise UnsafeRuleError(
                    f"Unknown Fieldnames member '{member_name}'"
                )

            return

        # Strictness.X
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == 'Strictness'
        ):
            member_name = node.attr

            if not hasattr(Strictness, member_name):
                raise UnsafeRuleError(
                    f"Unknown Strictness member '{member_name}'"
                )

            return

        raise UnsafeRuleError(
            f"Attribute access '{ast.unparse(node)}' is not allowed"
        )

    # ---------------------------------------------------------------
    # Constructor calls
    # ---------------------------------------------------------------

    if isinstance(node, ast.Call):

        if not isinstance(node.func, ast.Name):
            raise UnsafeRuleError(
                f"Only direct constructor calls are allowed: "
                f"'{ast.unparse(node)}'"
            )

        if node.func.id not in _ALLOWED_CONSTRUCTORS:
            raise UnsafeRuleError(
                f"Function '{node.func.id}' is not allowed"
            )

        # Reject *args.
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                raise UnsafeRuleError(
                    "*args unpacking is not allowed"
                )

            _validate_node(arg)

        # Reject **kwargs.
        for keyword in node.keywords:
            if keyword.arg is None:
                raise UnsafeRuleError(
                    "**kwargs unpacking is not allowed"
                )

            _validate_node(keyword.value)

        return

    # ---------------------------------------------------------------
    # Everything else is forbidden.
    # ---------------------------------------------------------------

    raise UnsafeRuleError(
        f"AST node '{type(node).__name__}' is not allowed"
    )


def _evaluate_node(node):
    """
    Evaluate a node that has already passed _validate_node().
    """

    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.List):
        return [
            _evaluate_node(element)
            for element in node.elts
        ]

    if isinstance(node, ast.Dict):
        return {
            _evaluate_node(key): _evaluate_node(value)
            for key, value in zip(node.keys, node.values)
        }

    if isinstance(node, ast.Name):
        return {
            'True': True,
            'False': False,
            'None': None,
        }[node.id]

    if isinstance(node, ast.Attribute):

        # Fieldnames.X.value
        if (
            node.attr == 'value'
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == 'Fieldnames'
        ):
            return getattr(
                Fieldnames,
                node.value.attr
            ).value

        # Strictness.X
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == 'Strictness'
        ):
            return getattr(
                Strictness,
                node.attr
            )

    if isinstance(node, ast.Call):

        constructor = _ALLOWED_CONSTRUCTORS[node.func.id]

        args = [
            _evaluate_node(arg)
            for arg in node.args
        ]

        kwargs = {
            keyword.arg: _evaluate_node(keyword.value)
            for keyword in node.keywords
        }

        return constructor(*args, **kwargs)

    raise UnsafeRuleError(
        f"Cannot evaluate AST node '{type(node).__name__}'"
    )


def _load_prules_from_file(filename):
    """
    Load valid PRules from a Python rule file.

    All module-level code is ignored. Only assignments to PRULES
    are considered.

    Individual PRules that fail AST validation or construction are
    silently skipped.
    """

    with open(filename, 'r', encoding='utf-8') as f:
        source = f.read()

    try:
        tree = ast.parse(
            source,
            filename=filename,
            mode='exec',
        )
    except SyntaxError:
        return []

    rules = []

    for statement in tree.body:

        # -----------------------------------------------------------
        # Ignore EVERYTHING except:
        #
        #     PRULES = [...]
        # -----------------------------------------------------------

        if not isinstance(statement, ast.Assign):
            continue

        if len(statement.targets) != 1:
            continue

        target = statement.targets[0]

        if not isinstance(target, ast.Name):
            continue

        if target.id != 'PRULES':
            continue

        # -----------------------------------------------------------
        # PRULES must be a literal list.
        # -----------------------------------------------------------

        if not isinstance(statement.value, ast.List):
            continue

        # -----------------------------------------------------------
        # Process each PRule independently.
        # -----------------------------------------------------------

        for i, rule_node in enumerate(statement.value.elts, start=1):

            try:
                # Validate before executing/constructing anything.
                _validate_node(rule_node)

                rule = _evaluate_node(rule_node)

                if not isinstance(rule, PRule):
                    continue

                rules.append(rule)

            except (UnsafeRuleError, TypeError, ValueError) as exc:
                # Invalid PRule: ignore it and continue
                logger.warning("Invalid or malicious rule detected. Rule %d: %s", i, str(exc))
                continue

    return rules

HEADER = '''#############################################################
# Parameter Definitions
#   PRule:
#       rule_id     (str)     : Name of the rule
#       precedence  (int >= 0): Order that the rules will be applied.
#                               Highest value is last, equal value is random amongst rules of the same value.
#       condition   (ConditionGroup OR Condition): Pass a Condition object if there is only 1 pattern that you want to match.
#                                                  Pass a ConditionGroup object if there is an expression of patterns you want to match.
#       replacement (dict)    : Dictionary of Fieldname enum values mapped to their respective replacement values
#
#   ConditionGroup:
#       operator    (str) : Choose among "AND", "OR", or "NOT"
#       conditions  (list): List of ConditionGroup or Condition objects (Note that 'NOT' operators only evaluate the first element and ignore the rest)
#
#   Condition:
#       fieldname   (Fieldname) : Target fieldname to match the pattern parameter to (e.g., Path, Line, Type)
#       pattern     (str)       : The pattern to match to the target fieldname's value (e.g., /proj/src/**/*.cpp)
#       strictness  (Strictness): Adjusts the strictness of the pattern matching. See below for Enum values.
#       case_sensitive (bool)   : True for case sensitive matching, False for case insensitive matching. Note that the strictness value 'EXACT' will not override this parameter.
#
#   Strictness:
#       EXACT (Will be case insensitive unless the case_sensitive flag is passed)
#       CONTAINS
#       STARTSWITH
#       ENDSWITH
#       GLOB  (Path Globbing, e.g. src/**/*.py)
#       REGEX (Regular Expression)
#
#
# Examples:
#       PRULES = [
#           #### This rule will match all paths with GLOB "source_dir/dir1/**/*.py"
#           PRule(
#               rule_id='example_single_condition',
#               precedence=1,
#               condition=Condition(fieldname=Fieldnames.PATH.value, pattern='source_dir/dir1/**/*.py', strictness=Strictness.GLOB, case_sensitive=False),
#               replacement={Fieldnames.SCORING_BASIS.value: '710', Fieldnames.CONFIDENCE.value: 'False Positive'}
#           ),
#
#           #### This rule will match: (Scanner contains "coverity" && Type exact matches "An expression with no side-effect or unintended effect indicates a possible logic flaw")
#           PRule(
#               rule_id='example_AND_conditions',
#               precedence=2,
#               condition=ConditionGroup(operator="AND", conditions=[
#                        Condition(fieldname=Fieldnames.SCANNER.value, pattern=r"coverity", strictness=Strictness.CONTAINS, case_sensitive=False),
#                        Condition(fieldname=Fieldnames.TYPE.value, pattern=r"An expression with no side-effect or unintended effect indicates a possible logic flaw", strictness=Strictness.EXACT, case_sensitive=False),
#                    ]),
#               replacement={Fieldnames.SCORING_BASIS.value: '710', Fieldnames.CONFIDENCE.value: 'Info'}
#           ),
#
#           #### This rule will match: ( (Path contains "src" || Path contains "include") && (Path endswith ".cpp") )
#           PRule(
#               rule_id='example_NESTED_AND_OR_conditions',
#               precedence=3,
#               condition=ConditionGroup("AND", [
#                     ConditionGroup("OR", [
#                         Condition(Fieldnames.PATH.value, "src", Strictness.CONTAINS),
#                         Condition(Fieldnames.PATH.value, "include", Strictness.CONTAINS)
#                     ]),
#                     Condition(Fieldnames.PATH.value, ".cpp", Strictness.ENDSWITH)
#                 ]),
#               replacement={Fieldnames.CONFIDENCE.value: 'Info', Fieldnames.VALIDATOR_COMMENT.value: "These are all the .cpp files in paths containing 'src' or 'include'"}
#           ),
#       ]
#############################################################

from parsers.parser_tools.prule import PRule, ConditionGroup, Condition, Strictness
from parsers.parser_tools.toolbox import Fieldnames

PRULES = [
'''

FOOTER = '''
]
'''
