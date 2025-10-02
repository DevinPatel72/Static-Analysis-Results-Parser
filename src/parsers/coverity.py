# coverity.py
import os
import logging
import traceback
import json
from .parser_tools import idgenerator, parser_writer
from .parser_tools.progressbar import SPACE, progress_bar
from .parser_tools.user_overrides import cwe_conf_override

logger = logging.getLogger(__name__)

def path_preview(fpath):
    # Open json in read
    try:
        with open(fpath, mode='r', encoding='utf-8-sig') as f:
            data = json.load(f)
            return data['issues'][0]['mainEventFilePathname']
    except Exception as e:
        return f"[ERROR] {e}"
    
def parse(fpath, scanner, substr, prepend, control_flags):
    from . import FLAG_CATEGORY_MAPPING, cwe_categories
    current_parser = __name__.split('.')[1]
    logger.info(f"Parsing {scanner} - {fpath}")
    
    # Count errors encountered while running
    err_count = 0

    # Open json in read
    try:
        with open(fpath, mode='r', encoding='utf-8-sig') as f:
            data = json.load(f)
    except:
        logger.error(f"File \'{fpath}\' failed to open:\n{traceback.format_exc()}")
        return err_count + 1
    
    # Keep track of issue number for debug
    issue_num = 0
    finding_count = 0
    total_issues = len(data['issues'])
    
    # Loop through every issue in json
    for issue in data['issues']:
        try:
            issue_num += 1
            progress_bar(issue_num, total_issues, prefix=f'Parsing {os.path.basename(fpath)}'.rjust(SPACE))
            
            cwe = issue['checkerProperties']['cweCategory']
            
            # Get tool cwe before any overrides are performed
            if len(cwe) <= 0:
                tool_cwe = '(blank)'
            else: tool_cwe = int(cwe) if str(cwe).isdigit() else cwe
            
            # Perform cwe overrides if user requests
            subcategoryLongDescription = issue['checkerProperties']['subcategoryLongDescription']
            cwe, confidence = cwe_conf_override(control_flags, override_name=subcategoryLongDescription, cwe=cwe, override_scanner=current_parser)
            
            # Check if cwe is in categories dict
            if control_flags[FLAG_CATEGORY_MAPPING] and cwe in cwe_categories.keys():
                cwe_cat = f"{cwe}:{cwe_categories[cwe]}"
            else:
                cwe_cat = int(cwe) if str(cwe).isdigit() else cwe
                
            # Find the main events
            mainEventsIdxs = []
            for i in range(len(issue['events'])):
                # If the entry is the main one, preserve the index
                if bool(issue['events'][i]['main']):
                    mainEventsIdxs.append(i)
                    
            # Parse events
            events = []
            if mainEventsIdxs[-1] < 8:
                # If less than 8 events, use all the events
                events = issue['events'][:mainEventsIdxs[-1]+1]
            elif len(mainEventsIdxs) == 1:
                # If only one main event, take first 3 and last 5
                beg = max(3, mainEventsIdxs[0]-4)
                end = max(3, mainEventsIdxs[0])
                events = issue['events'][:3] + ['...'] + issue['events'][beg:end+1]
            elif len(mainEventsIdxs) > 1:
                # If multiple main events, take first event, 2 events around the middle main events, and last 4 before last main event
                events.append(issue['events'][0])
                events.append(['...'])
                for idx in mainEventsIdxs[1:-1]:
                    beg = max(1, idx-1)
                    end = max(1, idx+1)
                    events = issue['events'][beg:end+1] + ['...']
                beg = max(0, idx[-1]-3)
                end = max(0, idx[-1])
                events += issue['events'][beg:end+1]
            else:
                # No main events, log the error and use all issues
                events = issue['events']
                logger.warning("Finding with mergekey {} has no main event. All events will be output, which may result in irregular formatting in the output csv.".format(issue['mergeKey']))
                err_count += 1
                
            # Strip trailing ellipses if there are any
            if events[-1] == ['...']:
                events.pop(-1)
            
            # Generate event descriptions in a single string
            eventDesc = ""
            for e in events:
                if e == '...':
                    eventDesc += "...\n"
                    continue
                t_path = str(e['filePathname']).replace(substr, "", 1)
                t_path = os.path.join(prepend, t_path).replace('\\', '/')
                eventDesc += "{}) {}:{}: {}\n".format(str(e['eventNumber']), t_path, str(e['lineNumber']), e['eventDescription'])
            eventDesc = eventDesc.strip()
            
            
            # Cut and prepend the paths and convert all backslashes to forwardslashes
            path = str(issue['mainEventFilePathname']).replace(substr, "", 1)
            path = os.path.join(prepend, path).replace('\\', '/')

            line = int(issue['mainEventLineNumber']) if str(issue['mainEventLineNumber']).isdigit() else issue['mainEventLineNumber']

            # Generate ID for Coverity finding (concat Path, Line, Scanner, and Message)
            preimage = f"{path}{issue['mainEventLineNumber']}{eventDesc}{tool_cwe}"
            id = idgenerator.hash(preimage)
            #id = "COV{:04}".format(finding_count+1)
            
            # Write row to outfile
            parser_writer.write_row({'CWE':cwe_cat,
                                'Confidence': confidence,
                                'Maturity': 'Proof of Concept',
                                'Mitigation': 'None',
                                'Mitigation Comment': '',
                                'Comment': '',
                                'ID': id,
                                'Type': subcategoryLongDescription,
                                'Path': path,
                                'Line': line,
                                'Symbol': issue['functionDisplayName'],
                                'Message': eventDesc,
                                'Tool CWE': tool_cwe,
                                'Tool':'',
                                'Scanner':scanner,
                                'Language':issue['language'].lower(),
                                'Severity':issue['checkerProperties']['impact']
                            })
            finding_count += 1
        except SystemExit as se:
            exit(se.code)
        except:
            logger.error(f"Issue {issue_num} of \'{fpath}\':\n{traceback.format_exc()}")
            err_count += 1
    logger.info(f"Successfully processed {finding_count} findings")
    logger.info(f"Number of erroneous findings: {err_count}")
    return err_count
# End of parse
