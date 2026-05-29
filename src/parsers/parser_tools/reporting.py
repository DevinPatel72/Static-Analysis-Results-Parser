# reporting.py

import logging
from .toolbox import console

_plotlib_enabled = False

try:
    import matplotlib.pyplot as plt
    _plotlib_enabled = True
except ImportError:
    _plotlib_enabled = False

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
        global _plotlib_enabled
        from parsers import GUI_MODE
        
        # Print CLI and log string here
        outstr = self._cli_table()

        logger.info('\n' + outstr + '\n')
        
        if not GUI_MODE:
            print(outstr)
        
        # Create pie charts
        if not _plotlib_enabled:
            console("Unable to generate plot charts because matplotlib failed to import. Skipping plot charts for reporting.", "Import Error", type='error')
            return
        
        total_findings, total_errors = self._get_total()

        findings = [i[0] for i in self.counts.values()]
        errors = [i[1] for i in self.counts.values()]
        labels = list(self.counts.keys())
        
        plt.pie(
            findings,
            labels=labels,
            autopct="%1.1f%%"
        )
        plt.title("Parse Results")
        plt.show()
    
    def save_chart(self):
        pass
    
    def _cli_table(self):
        _max_key_len = max([len(k) for k in self.counts.keys()])
        _max_val_len = max([len(str(v[0])) for v in self.counts.values()])
        
        outstr = "\nScanner{}\tFindings\tPercentage\tErrors".format(' '*(_max_key_len-len("Findings")-1))
        outstr += "\n—————————————————————————————————————————————————————————————\n"
        
        total_findings = self.get_total_findings()
        total_errors = self.get_total_errors()
        for k, v in self.counts.items():
            # Findings count
            percentage = f"{(v[0] / total_findings)*100:.1f}%"
            space = ' '*(_max_key_len-len(k))
            outstr += f"{k}:{space}\t{str(v[0]).rjust(_max_val_len)}\t\t{percentage.rjust(6)}"
            
            # Error count
            outstr += f"\t\t{v[1]}"
            outstr += '\n'
        
        # Calculate total
        space = ' '*(_max_key_len-len("Total")+1)
        outstr += f"\nTotal:{space}\t{str(total_findings).rjust(_max_val_len)}\t\t{"100.0%".rjust(6)}"
        total_errors = self.get_total_errors()
        outstr += f"\t\t{total_errors}"
        
        outstr += '\n'
        outstr += "—————————————————————————————————————————————————————————————"
        
        return outstr
