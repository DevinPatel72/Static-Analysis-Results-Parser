# reporting.py

import logging

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
        from parsers import GUI_MODE
        
        
        # Prep string here
        outstr = "\nFindings Report\n—————————————————————————————————————————————————————————————\n"
        outstr += str(self)
        outstr += "—————————————————————————————————————————————————————————————"

        logger.info('\n' + outstr + '\n')
        
        if not GUI_MODE:
            print(outstr)
        
    
    def save_chart(self):
        pass
    
    def __str__(self):
        _max_key_len = max([len(k) for k in self.counts.keys()])
        outstr = ""
        for k, v in self.counts.items():
            # Findings count
            space = ' '*(_max_key_len-len(k)+1)
            outstr += f"{k}:{space}{v[0]}"
            
            # Error count
            if v[1] > 0:
                outstr += f", Errors: {v[1]}"
            outstr += '\n'
        
        # Calculate total
        outstr += f"Total:{space}{self.get_total_findings()}"
        err_count = self.get_total_errors()
        if err_count > 0:
            outstr += f", Errors: {err_count}"
        outstr += '\n'
        
        return outstr
