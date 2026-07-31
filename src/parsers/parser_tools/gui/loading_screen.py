# loading_screen.py

import re
import queue
import parsers
from ..toolbox import InputConfigFlags
import tkinter as tk
from tkinter import ttk

class LoadingWindow:
    def __init__(self, root, scanner_ids):

        self.root = tk.Toplevel(root)
        self.queue = queue.Queue()
        self.cleanexit = False

        self.root.title(parsers.PROG_NAME)

        self.progress_widgets = {}
        self.completed = set()
        self.expected = set()

        ############################################################
        # Create one progress bar per scanner
        ############################################################

        row = 0

        for input_id in scanner_ids:

            label = ttk.Label(
                self.root,
                text="Waiting..."
            )
            label.grid(
                row=row,
                column=0,
                sticky="w",
                padx=10,
                pady=(8, 0)
            )

            progress = ttk.Progressbar(
                self.root,
                mode="determinate",
                maximum=100,
                length=450
            )
            progress.grid(
                row=row + 1,
                column=0,
                padx=10,
                pady=(0, 8),
                sticky="ew"
            )

            self.progress_widgets[input_id] = {
                "label": label,
                "bar": progress
            }

            self.expected.add(input_id)

            row += 2

        ############################################################
        # Control Flag progress bars
        ############################################################

        CONTROL_FLAG_BARS = [
            (
                InputConfigFlags.DUPE_SCAN_CONSOLIDATION.flag,
                                f"Waiting for {InputConfigFlags.DUPE_SCAN_CONSOLIDATION.flag}...",
                InputConfigFlags.DUPE_SCAN_CONSOLIDATION.flag,
            ),
            (
                InputConfigFlags.PREFLIGHT_RULES.flag,
                f"Waiting for {InputConfigFlags.PREFLIGHT_RULES.flag}...",
                InputConfigFlags.PREFLIGHT_RULES.flag,
            ),
            (
                InputConfigFlags.OVERRIDE_VULN_MAPPING.flag,
                f"Waiting for {InputConfigFlags.OVERRIDE_VULN_MAPPING.flag}...",
                InputConfigFlags.OVERRIDE_VULN_MAPPING.flag,
            ),
        ]

        for progress_id, waiting_text, flag_name in CONTROL_FLAG_BARS:
            if flag_name not in parsers.control_flags.keys() or parsers.control_flags[flag_name]:
                continue

            label = ttk.Label(
                self.root,
                text=waiting_text
            )
            label.grid(
                row=row,
                column=0,
                sticky="w",
                padx=10,
                pady=(8, 0)
            )

            progress = ttk.Progressbar(
                self.root,
                mode="determinate",
                maximum=100,
                length=450
            )
            progress.grid(
                row=row + 1,
                column=0,
                padx=10,
                pady=(0, 8),
                sticky="ew"
            )

            self.progress_widgets[progress_id] = {
                "label": label,
                "bar": progress
            }

            self.expected.add(progress_id)

            row += 2

        ############################################################
        # Center the window
        ############################################################

        self.root.update_idletasks()

        current_geometry = self.root.winfo_toplevel().geometry()

        if (m := re.match(r"(\d+)x(\d+)\+(\d+)\+(\d+)", current_geometry)):
            width = int(m.group(1))
            height = int(m.group(2))
        else:
            width = 500
            height = row * 35

        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        x = (screen_width - width) // 2
        y = (screen_height - height) // 2 - 50

        self.root.geometry(f"{width}x{height}+{x}+{y}")

        self.root.after(100, self.poll_queue)

    ###########################################################################

    def poll_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()

                msg_type = msg.get("type")

                ###############################################################
                # Progress update
                ###############################################################

                if msg_type == "progress":
                    self.update_progress(msg)

                ###############################################################
                # Individual task completed
                ###############################################################

                elif msg_type == "complete":
                    progress_id = msg["id"]

                    if progress_id in self.progress_widgets:
                        widgets = self.progress_widgets[progress_id]

                        widgets["bar"]["value"] = 100

                        self.completed.add(progress_id)

                    if self.completed >= self.expected:
                        self.cleanexit = True
                        self.root.destroy()
                        return

                ###############################################################
                # Force close
                ###############################################################

                elif msg_type == "stop":
                    self.root.destroy()
                    return

        except queue.Empty:
            pass

        self.root.after(100, self.poll_queue)

    ###########################################################################

    def update_progress(self, msg):
        progress_id = msg["id"]

        widgets = self.progress_widgets.get(progress_id)

        if widgets is None:
            return

        widgets["bar"]["value"] = msg.get("percent", 0)

        widgets["label"].config(
            text=msg.get("status", "")
        )
