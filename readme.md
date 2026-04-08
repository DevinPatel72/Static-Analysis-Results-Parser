# Static Analysis Results Parser

## Description
The Static Analysis Results Parser (SARP) will parse a set of output files from static analysis tools and collect them into one Excel or CSV file. Inputs can be entered via GUI or [json input](#configure-bulk-inputs). [Preflight override rules](#configure-preflight) can be defined in the config directory.

### Accepted Inputs:
-  SARP:        `.xlsx` or `.csv`
-  Checkmarx:   Directory of `.xml` (preferred) or `.csv` files (Single directory, no recursion)
-  CppCheck:    `.xml`
-  Coverity:    `.json`
-  OWASP Dependency Check: `.json` or `.csv`
-  ESLint:      `.json`
-  Fortify:     `.fpr`
-  Gnat SAS:    `.json (aka SARIF format)` (preferred) or `.csv`
-  NVD CVE:     `.csv` (See [Batch-NVD-CVE](https://github.com/DevinPatel72/Batch-NVD-Query))
-  Pragmatic:   `.csv`
-  Pylint:      `.json`
-  Semgrep:     `.json` (preferred) or `.csv`
-  Sigasi:      `.json`
-  SRM:         `.xml` (preferred) or `.csv`


## Execute using binaries

**Requirements:**
- Ensure the config folder is in the same directory as the executables.

**Instructions:**
- Double-click on the binary or execute them from the command line.
- No external dependencies are required to execute the binaries.



## Execute using interpreter

**Dependencies:**

Though not required, SARP does use external modules for certain features.

```bash
$ pip install -r requirements.txt
```

**Execution:**

```bash
$ python3 parse-cli.py
  --or--
$ python3 parse-gui.py
```


## Build instructions

**Requirements:**

External modules `tkinter`, `openpyxl`, and `pyinstaller` must be installed.

```bash
$ pip install pyinstaller openpyxl
```

`tkinter` must be installed system-wide. Methods vary for [Windows](https://www.pythonguis.com/installation/install-tkinter-windows/) and [Linux](https://www.pythonguis.com/installation/install-tkinter-linux/).

Then execute the build script.


## Configure Bulk Inputs
A user-writable config file can be created to quickly pass inputs in bulk.
To generate this config file, run the parser once against valid input and check the config folder for "user_inputs.json."
If any loaded data is changed in the guided prompts or GUI, "user_inputs.json" will be overwritten with the new data.

## Configure CWE Mappings
SARP allows configurable CWE mappings for scanners that do not output CWE data. A basic set of mappings are provided,
but users are able to edit and share them if they wish.

## Configure Preflight
SARP can perform user-defined overrides on any of the output fields using rule expressions and extended matching techniques.

### Match Patterns
Each rule contains a condition that attempts to match a Fieldname value to a user-defined pattern. If a match is found, the condition is resolved to true.

Patterns can be matched according to the following techniques:
- Exact (Will be case insensitive unless optioned otherwise)
- Contains
- StartsWith
- EndsWith
- Glob (Path Globbing, e.g. src/*\*/\*.cpp)
- Regular Expression

### Chaining Condition Expressions
Each rule can contain condition groups that apply a boolean operator to each of the conditions within the group.
- AND (All conditions in the group must evaluate to True)
- OR (At least one condition in the group must evaluate to True)
- NOT (Only the first conditon is negated. ***All others are ignored.***)

A condition group can contain another condition group to create nested boolean expressions. Note that every condition group must contain at least one condition.

### Rule Ordering
A precedence ordering can be applied to each rule. The rules will be applied from least to greatest, so subsequent rules will overwrite any overrides done in preceding rules.

### Examples
#### Example 1
![Example1](docs/images/Example1.png)

The above `Rule1` looks for an exact match for the value in field `Scoring Basis` (e.g., a CWE or CVE ID) and replaces the `Scoring Basis` with *710* and `Confidence` with *Info*.

Expression: `Scoring Basis == 398`

#### Example 2
![Example2](docs/images/Example2.png)

The above `Rule2` looks for any finding that is in a `.cpp` file **AND** contains *nullptr* in the `Type` column. The `Scoring Basis` is replaced with *476* and the `Validator Justification` is replaced with *Insert validator comment here*.

Expression: `(Path glob "**/*.cpp") && ("nullptr" in Type)`

#### Example 3
![Example3](docs/images/Example3.png)

The above `Rule3` looks for any finding that originates from either CPPCheck **OR** SRM, **AND** it is either of `Type` *nullPtrDeref* **OR** contains *Null Pointer*. The `Scoring Basis` is replaced with *476*.

Expression: `("cppcheck" in Scanner || "srm" in Scanner) && (Type == "nullPtrDeref" || "Null Pointer" in Type)`
