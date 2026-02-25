# prule.py

from enum import Enum
import fnmatch
import re

# Implementation for a rule expression tree

class Strictness(str, Enum):
    EXACT = ("Exact", lambda v, p: v == p)
    CONTAINS = ("Contains", lambda v, p: p in v)
    STARTSWITH = ("Starts with", lambda v, p: v.startswith(p))
    ENDSWITH = ("Ends with", lambda v, p: v.endswith(p))
    GLOB = ("Glob", lambda v, p: fnmatch.fnmatch(v, p))
    REGEX = ("Regex", lambda v, p: re.search(p, v) is not None)

    def __new__(cls, value, func):
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.func = func
        return obj

    def matches(self, value, pattern, case_sensitive=False):
        if case_sensitive:
            return self.func(value, pattern)
        else:
            value = value.lower() if isinstance(value, str) else value
            pattern = pattern.lower() if isinstance(pattern, str) else pattern
            return self.func(value, pattern)


class Condition:

    def __init__(self, fieldname, pattern, strictness=Strictness.CONTAINS, case_sensitive=False):
        self.fieldname = fieldname
        self.pattern = pattern
        self.strictness = strictness
        self.case_sensitive = case_sensitive

    def evaluate(self, target):
        if self.fieldname not in target:
            return False

        value = target[self.fieldname]
        return self.strictness.matches(str(value), str(self.pattern), case_sensitive=self.case_sensitive)
    
    def to_dict(self):
        return {
            "type": "condition",
            "fieldname": self.fieldname,
            "pattern": self.pattern,
            "strictness": self.strictness.value,
            "case_sensitive": self.case_sensitive
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            fieldname=data["fieldname"],
            pattern=data["pattern"],
            strictness=Strictness(data["strictness"]),
            case_sensitive=data["case_sensitive"]
        )


class RuleGroup:

    def __init__(self, operator="AND", rules=None):
        self.operator = operator.upper()
        self.rules = rules if rules is not None else []

    def evaluate(self, target):

        if self.operator == "AND":
            return all(rule.evaluate(target) for rule in self.rules)

        elif self.operator == "OR":
            return any(rule.evaluate(target) for rule in self.rules)

        elif self.operator == "NOT":
            return not self.rules[0].evaluate(target)

        else:
            raise ValueError(f"Unknown operator {self.operator}")
    
    def to_dict(self):
        return {
            "type": "group",
            "operator": self.operator,
            "rules": [rule.to_dict() for rule in self.rules]
        }

    @classmethod
    def from_dict(cls, data):

        rules = []

        for rule_data in data["rules"]:

            if rule_data["type"] == "condition":
                rules.append(Condition.from_dict(rule_data))

            elif rule_data["type"] == "group":
                rules.append(RuleGroup.from_dict(rule_data))

        return cls(
            operator=data["operator"],
            rules=rules
        )

class PRule:

    def __init__(self, rule_id="", precedence=0, condition=None, replacement=None):
        
        self.rule_id = rule_id
        
        if not isinstance(precedence, int) or (isinstance(precedence, int) and precedence < 0):
            raise ValueError("Parameter 'precedence' must be a positive, nonzero integer")
        
        self.precedence = precedence
        self.condition = condition
        self.replacement = replacement if replacement is not None else {}

    def check_rule(self, target):
        return self.condition.evaluate(target)

    def apply_rule(self, target):
        if self.check_rule(target):
            return self.replacement
        return None
    
    def to_dict(self):

        return {
            "rule_id": self.rule_id,
            "precedence": self.precedence,
            "condition": self.condition.to_dict(),
            "replacement": self.replacement
        }

    @classmethod
    def from_dict(cls, data):

        condition_data = data["condition"]

        if condition_data["type"] == "condition":
            condition = Condition.from_dict(condition_data)
        else:
            condition = RuleGroup.from_dict(condition_data)

        return cls(
            rule_id=data['rule_id'],
            precedence=data["precedence"],
            condition=condition,
            replacement=data["replacement"]
        )


