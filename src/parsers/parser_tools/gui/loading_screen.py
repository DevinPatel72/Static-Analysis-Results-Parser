# loading_screen.py

import re
import parsers
from . import center_window
from ..toolbox import InputConfigFlags, GuiWindow
import tkinter as tk
from tkinter import ttk
from queue import Empty

class LoadingWindow:
    def __init__(self, root, scanner_ids, progress_queue):

        self.root = tk.Toplevel(root)
        self.queue = progress_queue
        self.cleanexit = False

        self.root.title(parsers.PROG_NAME)

        self.progress_widgets = {}
        self.completed = set()
        self.expected = set()

        ############################################################
        # Create one progress bar per scanner
        ############################################################
        ttk.Label(
            self.root,
            text="Scanners",
            font=("TkDefaultFont", 10, "bold")
        ).pack(
            padx=10,
            pady=(10, 5)
        )
        
        row = 0
        
        scanner_content = ttk.Frame(self.root, padding=10)
        scanner_content.pack(fill="both", expand=True)

        scanner_content.columnconfigure(0, weight=1)
        scanner_content.columnconfigure(1, weight=0)

        row += 1
        
        for scanner_fpath, input_id in scanner_ids:

            scanner_content.grid_columnconfigure(0, weight=1)
            scanner_content.grid_columnconfigure(1, weight=0)

            header = ttk.Frame(scanner_content)
            header.grid(row=row, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 5))

            header.columnconfigure(0, weight=1)

            status = ttk.Label(header, text=f"Initializing {scanner_fpath}")
            status.grid(row=0, column=0, sticky="w")

            percent = ttk.Label(header, text="0 %")
            percent.grid(row=0, column=1, sticky="e")

            progress = ttk.Progressbar(
                scanner_content,
                mode="determinate",
                maximum=100,
                length=450
            )
            progress.grid(
                row=row + 1,
                column=0,
                columnspan=2,
                sticky="ew",
            )

            self.progress_widgets[input_id] = {
                "status": status,
                "percent": percent,
                "bar": progress
            }

            self.expected.add(input_id)

            row += 2

        ############################################################
        # Control Flag progress bars
        ############################################################

        CONTROL_FLAG_BARS = [
            (f.flag, f"{f.flag}: Waiting for scanners to finish parsing...", f.flag)
            for f in InputConfigFlags
            if GuiWindow.LoadingWindow in f.module_visibility
        ]
        
        enabled = [
            item for item in CONTROL_FLAG_BARS
            if parsers.control_flags.get(item[2], False)
        ]

        if enabled:
            ttk.Separator(self.root, orient="horizontal").pack(
                padx=10,
                pady=(10, 5)
            )

            ttk.Label(
                self.root,
                text="Post Processing",
                font=("TkDefaultFont", 10, "bold")
            ).pack(
                padx=10,
                pady=(0, 5)
            )
        
        row = 0
        
        post_content = ttk.Frame(self.root, padding=10)
        post_content.pack(fill="both", expand=True)

        post_content.columnconfigure(0, weight=1)
        post_content.columnconfigure(1, weight=0)

        for progress_id, waiting_text, flag_name in CONTROL_FLAG_BARS:
            if flag_name not in parsers.control_flags.keys() or not parsers.control_flags[flag_name]:
                continue

            post_content.grid_columnconfigure(0, weight=1)
            post_content.grid_columnconfigure(1, weight=0)
            
            post_header = ttk.Frame(post_content)
            post_header.grid(row=row, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 5))
            
            post_header.columnconfigure(0, weight=1)
            
            status = ttk.Label(post_header, text=waiting_text)
            status.grid(row=0, column=0, sticky="w")
            
            percent = ttk.Label(post_header, text="0 %")
            percent.grid(row=0, column=1, sticky="e")

            progress = ttk.Progressbar(
                post_content,
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
                "status": status,
                "percent": percent,
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

        center_window(self.root, width, height)

        self.root.after(100, self.poll_queue)
        
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.root.attributes("-topmost", True)
        self.root.update()
        self.root.attributes("-topmost", False)

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
                        widgets["status"].config(text=msg.get("status", ""))
                        widgets["percent"].config(text="100 %")

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

        except Empty:
            pass

        self.root.after(100, self.poll_queue)

    ###########################################################################

    def update_progress(self, msg):
        progress_id = msg["id"]

        widgets = self.progress_widgets.get(progress_id)

        if widgets is None:
            return

        widgets["bar"]["value"] = msg.get("percent", 0)

        widgets["status"].config(text=msg.get("status", ""))
        widgets["percent"].config(text="{:.0f} %".format(msg.get("percent", 0)))
