# loading_gui.py

import logging
import threading
import queue
import tkinter as tk
from tkinter import ttk

from .. import PROG_NAME, VERSION

# Constants
WINDOW_LENGTH = 720
WINDOW_HEIGHT = 580
WINDOW_TITLE = PROG_NAME

class TkLogHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put((
            record.levelname,
            self.format(record)
        ))

class LoadingGUI:
    def __init__(self, scanners):
        self.scanners = scanners
        self.cancel_event = threading.Event()
        self.log_queue = queue.Queue()
        self.finished = False

        self.root = tk.Tk()
        self.root.title("Processing Scanners")
        self.root.geometry(f"{WINDOW_LENGTH}x{WINDOW_HEIGHT}")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        main = tk.Frame(self.root, padx=10, pady=10)
        main.pack(fill="both", expand=True)

        # ---------------- Overall Status ----------------
        self.overall_status = tk.StringVar(value="Running...")
        tk.Label(
            main,
            textvariable=self.overall_status,
            font=("Segoe UI", 10, "bold"),
            anchor="w"
        ).pack(fill="x", pady=(0, 5))

        # ---------------- Scanner Progress ----------------
        progress_frame = tk.LabelFrame(main, text="Scanner Progress")
        progress_frame.pack(fill="x", pady=(0, 10))

        self.scanner_widgets = {}
        for scanner in scanners:
            self._add_scanner_row(progress_frame, scanner)

        # ---------------- Log Output ----------------
        log_frame = tk.LabelFrame(main, text="Log Output")
        log_frame.pack(fill="both", expand=True)

        self.log_text = tk.Text(log_frame, wrap="word", state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True)

        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.tag_configure(
            "ERROR",
            foreground="red",
            font=("Segoe UI", 9, "bold")
        )

        self.log_text.tag_configure(
            "CRITICAL",
            foreground="red",
            font=("Segoe UI", 9, "bold")
        )

        # ---------------- Controls ----------------
        controls = tk.Frame(main)
        controls.pack(fill="x", pady=(5, 0))

        self.action_btn = tk.Button(
            controls,
            text="Cancel",
            bg="#b00020",
            fg="white",
            command=self.cancel
        )
        self.action_btn.pack(side="right")

        self.ui_queue = queue.Queue()
        self.root.after(100, self._poll_log_queue)
        self.root.after(50, self._poll_ui_queue)
        
        # Version text
        version_label = tk.Label(self.root, text=f"{PROG_NAME} {VERSION}", font=("Arial", 8), fg="gray")
        version_label.pack(side="bottom", pady=5)

    # -------------------------------------------------
    # Scanner Rows
    # -------------------------------------------------

    def _add_scanner_row(self, parent, scanner):
        row = tk.Frame(parent)
        row.pack(fill="x", pady=3)

        tk.Label(row, text=scanner, width=18, anchor="w").pack(side="left")

        bar = ttk.Progressbar(row, maximum=100)
        bar.pack(side="left", fill="x", expand=True, padx=5)

        status = tk.StringVar(value="Pending")
        tk.Label(row, textvariable=status, width=14, anchor="w").pack(side="left")

        self.scanner_widgets[scanner] = {"bar": bar, "status": status}

    # -------------------------------------------------
    # Public API
    # -------------------------------------------------
    
    def queue_scanner_update(self, scanner, percent=None, status=None):
        self.ui_queue.put((scanner, percent, status))
    
    def mainloop(self):
        self.root.mainloop()

    def update_scanner(self, scanner, percent=None, status=None):
        w = self.scanner_widgets.get(scanner)
        if not w:
            return
        if percent is not None:
            w["bar"]["value"] = percent
        if status:
            w["status"].set(status)
        self.root.update_idletasks()

    def mark_complete(self, scanner):
        self.update_scanner(scanner, 100, "Done")

    def mark_all_complete(self):
        self.finished = True
        self.overall_status.set("Completed")
        self.action_btn.config(
            text="Close",
            bg="#4caf50",
            command=self.close
        )

    def cancelled(self):
        return self.cancel_event.is_set()

    def cancel(self):
        self.cancel_event.set()
        self.overall_status.set("Cancelling...")
        self.action_btn.config(state="disabled")

    def close(self):
        self.root.destroy()

    def _on_close(self):
        # Prevent accidental close while running
        if not self.finished:
            return
        self.close()

    # -------------------------------------------------
    # Logging
    # -------------------------------------------------

    def attach_logger(self, logger):
        handler = TkLogHandler(self.log_queue)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def _poll_log_queue(self):
        while not self.log_queue.empty():
            level, msg = self.log_queue.get_nowait()
            self._append_log(level, msg)
        self.root.after(100, self._poll_log_queue)
        
    def _poll_ui_queue(self):
        while not self.ui_queue.empty():
            scanner, percent, status = self.ui_queue.get_nowait()
            self._apply_scanner_update(scanner, percent, status)
        self.root.after(50, self._poll_ui_queue)
    
    def _apply_scanner_update(self, scanner, percent, status):
        w = self.scanner_widgets.get(scanner)
        if not w:
            return

        if percent is not None:
            w["bar"]["value"] = max(0, min(100, percent))

        if status:
            w["status"].set(status)

    def _append_log(self, level, message):
        self.log_text.configure(state="normal")

        tag = level if level in ("ERROR", "CRITICAL", "WARNING", "INFO") else None

        if tag:
            self.log_text.insert("end", message + "\n", tag)
        else:
            self.log_text.insert("end", message + "\n")

        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        