# Change Log

## [Version 1.0.0](https://) (2025-08-25)




## Beta Versions

### Beta v20250818
    Parser now accepts user input in a config file "user_inputs.json".
    To see formatting, run the parser once against valid input and check the config folder.

### Beta v20250814:
    Parser now outputs as an Excel workbook by default UNLESS one of the following is true:
        1) The user requests CSV via prompt
        2) The user enters an outfile with a .csv extension
        3) External module "openpyxl" is not installed when running from src
    Minor bug fixes and fine-tuning.

### Beta v20250805:
    A GUI version has been created.
    Please note that compatibility testing with legacy versions of python3 has not been performed, so older python3 versions may not be able to run the GUI.
    If this is the case, you may have to run the executables or update your python version.
	
	Significantly reworked the parser to be packaged as an executable that can be run without a python interpretor or the script dependencies.
    As of now, 64-bit executables have been built for Windows 10 and Ubuntu Linux. Support for other platforms can be requested.
	The source is still provided in case the executables do not work or if a user wants to add a custom feature.
    See section Execution Instructions for executing from source.

### Beta v20250730:
    Implemented de-duping for OWASP DepCheck findings. OWASP has been found to output the same CVE number for multiple .dlls and .exes.
    The parser will now mark one CVE number as Confirmed and any rows with the same CVE as Duplicate.

    User overrides for AIO parser, OWASP DepCheck, and Manual CVEs now work.

### Beta v20250717:
    User-defined CWE and Confidence overrides.
    Control flags for those overrides.
    See Note 2 for details on how to define override rules.
    
    ESLint parser now skips parser errors and ruleIDs that are null.

    Minor improvements to terminal UI.

### Beta v20250716:
    Fixed bugs in input validation for CSVs created from AIO parser.
    Made minor changes in how Fortify messages are parsed.
    Fixed minor bug where the progress bar for Checkmarx did not calculate the total number of CSV rows correctly.

### Beta v20250709:
    Added support for parsing AIO output CSVs. It will copy all findings from the input to the output.

### Beta v20250708:
    Fixed a bug where a Windows absolute path will cause issues in guided prompts.
    Use commas to delineate file path and scanner, and use quotation marks to escape commas in file paths.

    Changed the line endings of all files from CRLF to LF for easier use on Linux systems.
    Limited testing showed that Windows interpretors will accept LF line endings.
    Note that older Python interpretors on Windows may not function well with LF line endings.

    Included an independent tool "Fetch NVD CVEs" to fetch CVE information when given a set of CVE numbers.
    This tool requires access to the internet and its output can be passed into parse.py.
    The script contains a header with instructions on installing dependencies and usage.

### Beta v20250626:
    Fixed a bug where Pylint type and message columns were identical

### Beta v20250610:
    Added more CWEs to Vulnerability Mappings that were not covered in Dependency Check output

### Beta v20250606:
    Added support for ESLint
    Added support for manually fetched CVEs. It is recommended to use the script "Fetch NVD CVEs/fetch-nvd-cve.py" to generate the csv file.

### Beta v20250519:
    Added a switch to turn off CWE vulnerability mappings in the output file. It is on by default.
    Fixed a bug where the coverity event history is not output correctly

### Beta v20250516:
	Improved validity checks for file path inputs

### Beta v20250430:
	Added support for OWASP Dependency Check
	Fixed bug where Coverity events were dropped from the message column
	Updated CWE 665 from vulnerability mapping "CATEGORY" to "DISCOURAGED"

### Beta v20250224:
    Added an "ls" command to quickly view file names when entering scanner input files using guided prompts

### Beta v20250221:
    Updated Fortify to significantly reduce long trace messages

### Beta v20250205:
    Added two CppCheck message IDs to the list of informational IDs: templateRecursion, checkLevelNormal

### Beta v20250129:
	Updated CppCheck parser to print filtered config errors to a CSV instead of the logfile
    Updated Coverity to significantly reduce clutter in the Message column

### Beta v20250124:
    Updated Fortify parser to accomodate for certain missing XML tags and other minor fixes. Added new language_resolver module and included more file extentions.

### Beta v20250123:
    Beta parser is ready for distribution.
```
