# initialization.py

import os
import sys
import parsers
from parsers.parser_tools import progressbar, parser_logger as logger


def init_globals(gui_mode=False, progressbar_space=34):
    # Init GUI if true
    if gui_mode:
        import tkinter as tk
        parsers.gui_root = tk.Tk()
        parsers.gui_root.withdraw()
    parsers.GUI_MODE = gui_mode
    progressbar.DISABLE_PROGRESS_BAR = gui_mode
    progressbar.SPACE = progressbar_space
    
    # Configure root path and important dirs of script
    if getattr(sys, 'frozen', False):
        # Running as bundled executable
        parsers.EXE_ROOT_DIR = os.path.dirname(sys.executable)
        logname = os.path.splitext(os.path.basename(sys.executable))[0]+'.log'
        parsers.ASSETS_DIR = os.path.join(sys._MEIPASS, parsers.ASSETS_DIR)
        parsers.LOGO_PATH = os.path.join(parsers.ASSETS_DIR, 'logos', 'sarp-logo-256.png')
        if not os.path.isfile(parsers.LOGO_PATH):
            parsers.LOGO_PATH = os.path.join(parsers.ASSETS_DIR, 'logos', 'sarp-logo-1024.png')
    else:
        # Running as script
        parsers.EXE_ROOT_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
        logname = os.path.splitext(os.path.basename(os.path.abspath(sys.argv[0])))[0]+'.log'
        parsers.ASSETS_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.ASSETS_DIR)
        parsers.LOGO_PATH = os.path.join(parsers.ASSETS_DIR, 'logos', 'sarp-logo-256.png')
        if not os.path.isfile(parsers.LOGO_PATH):
            parsers.LOGO_PATH = os.path.join(parsers.ASSETS_DIR, 'logos', 'sarp-logo-1024.png')

    # Capitalized drive letter if on Windows
    drive, rest = os.path.splitdrive(parsers.EXE_ROOT_DIR)
    if len(drive) > 0: drive = drive.upper()
    parsers.EXE_ROOT_DIR = os.path.join(drive, rest)

    # Set import directories
    parsers.CONFIG_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.CONFIG_DIR)
    parsers.MAPPINGS_DIR = os.path.join(parsers.CONFIG_DIR, parsers.MAPPINGS_DIR)
    parsers.PREFLIGHT_DIR = os.path.join(parsers.CONFIG_DIR, parsers.PREFLIGHT_DIR)

    # Create inputs directory
    parsers.INPUTS_DIR = os.path.join(parsers.CONFIG_DIR, parsers.INPUTS_DIR)
    os.makedirs(parsers.INPUTS_DIR, exist_ok=True)

    # Set log paths
    parsers.LOGS_DIR = os.path.join(parsers.EXE_ROOT_DIR, parsers.LOGS_DIR)
    os.makedirs(parsers.LOGS_DIR, exist_ok=True)
    parsers.LOGFILE = os.path.join(parsers.LOGS_DIR, logname)

def init_main_logger():
    logger.initialize_main(parsers.LOGFILE)
    
    # Include date and time of execution at the top of the logger
    from datetime import datetime
    logger.info("%s %s", parsers.PROG_NAME, parsers.VERSION)
    logger.info(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
