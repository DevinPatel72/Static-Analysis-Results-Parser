# reporting.py

import logging
from enum import Enum
import parsers

__plotlib_enabled = False

try:
    import matplotlib
    __plotlib_enabled = True
except ImportError:
    __plotlib_enabled = False

logger = logging.getLogger(__name__)

class Report:
    """
    Reporting class to track finding counts and generate images and reports at the end of parsing.\n
    CLI Mode: Print counts and their percentages. Enable command line option to disable pie chart output to log directory.\n
    GUI Mode: Display pie chart and individual counts in a table in a Tkinter window at the very end.
    """
    
    def __init__(self, scanners):
        # Init the counts [findings, errors]
        self.counts = {}
        for scanner in scanners:
            self.counts[scanner] = [0, 0]
        self.counts['Total'] = [0, 0]
    
    def _get_total(self):
        return self.counts['Total']
    
    def get_total_findings(self):
        return self.counts['Total'][0]
    
    def get_total_errors(self):
        return self.counts['Total'][1]
    
    def inc_total_findings(self, add):
        self.counts['Total'][0] += add
        
    def inc_total_errors(self, add):
        self.counts['Total'][1] += add
    
    def generate_report(self):
        pass
    
    def save_chart(self):
        pass
    
    
    def __str__(self):
        return str(self.counts)
        


