# gui
import tkinter as tk
from ... import PROG_NAME

# GUI Constants
WINDOW_LENGTH = 900
WINDOW_HEIGHT = 525
WINDOW_TITLE = PROG_NAME

FORMAT_MAP = {
    "Excel": {
        "ext": ".xlsx",
        "filetype": ("Excel Workbook", "*.xlsx"),
    },
    "SARIF": {
        "ext": ".sarif",
        "filetype": ("SARIF", "*.sarif"),
    },
    "CSV": {
        "ext": ".csv",
        "filetype": ("CSV Files", "*.csv"),
    },
}

EXT_TO_FORMAT = {
    v["ext"]: k
    for k, v in FORMAT_MAP.items()
}

# GUI Functions
def create_tk_variable(value, master=None):
    var_type = {
        int: tk.IntVar,
        bool: tk.BooleanVar,
        float: tk.DoubleVar,
        str: tk.StringVar,
    }.get(type(value), tk.StringVar)
    return var_type(master=master, value=value)
