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
    CLI Mode: Print counts and their percentages. Outputs a pie chart image to logs directory.\n
    GUI Mode: Display pie chart and individual counts in a table in a Tkinter window at the very end. Save image out to log directory.
    """
    
    def __init__(self, scanners):
        # Init the counts [findings, errors]
        self.counts = {scanner: [0, 0] for scanner in scanners}
    
    def _get_total(self):
        return [self.get_total_findings(), self.get_total_errors()]
    
    def get_total_findings(self):
        return sum([v[0] for v in self.counts.values()])
    
    def get_total_errors(self):
        return sum([v[1] for v in self.counts.values()])

    def generate_report(self):
        pass
    
    def save_chart(self):
        pass
    
    def __str__(self):
        return str(self.counts)
        


