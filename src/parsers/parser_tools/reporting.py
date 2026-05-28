# reporting.py

import logging

logger = logging.getLogger(__name__)

"""
Reporting class to track finding counts and generate images and reports at the end of parsing
"""

class Report:
    def __init__(self):
        # Init the counts
        self.aio_count = 0
        self.checkmarx_count = 0
        self.coverity_count = 0
        self.cppcheck_count = 0
        self.eslint_count = 0
        self.fortify_count = 0
        self.gnatsas_count = 0
        self.manual_cwe_count = 0
        self.depcheck_count = 0
        self.pragmatic_count = 0
        self.pylint_count = 0
        self.semgrep_count = 0
        self.sigasi_count = 0
        self.srm_count = 0
        self.total_findings = 0
        
        

