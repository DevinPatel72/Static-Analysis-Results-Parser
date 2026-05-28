# reporting.py

import logging
import parsers

logger = logging.getLogger(__name__)


class Report:
    """
    Reporting class to track finding counts and generate images and reports at the end of parsing.\n
    CLI Mode: Print counts and their percentages. Enable command line option to disable pie chart output to log directory.\n
    GUI Mode: Display pie chart and individual counts in a table in a Tkinter window at the very end.
    """
    
    def __init__(self):
        # Init the counts (findings, errors)
        self.aio_count =        [0, 0]
        self.checkmarx_count =  [0, 0]
        self.coverity_count =   [0, 0]
        self.cppcheck_count =   [0, 0]
        self.eslint_count =     [0, 0]
        self.fortify_count =    [0, 0]
        self.gnatsas_count =    [0, 0]
        self.manual_cwe_count = [0, 0]
        self.depcheck_count =   [0, 0]
        self.pragmatic_count =  [0, 0]
        self.pylint_count =     [0, 0]
        self.semgrep_count =    [0, 0]
        self.sigasi_count =     [0, 0]
        self.srm_count =        [0, 0]
        self.total_count =      [0, 0]
    
    def generate_report(self):
        pass
    
    def save_chart(self):
        pass
        
        

