# loading_screen.py

import re
from parsers import PROG_NAME
from dataclasses import dataclass
import queue
import tkinter as tk
from tkinter import ttk

@dataclass
class ProgressUpdate:
    scanner: str
    current: int
    total: int
    status: str

class LoadingWindow:
    def __init__(self, root):
        self.root = tk.Toplevel(root)
        self.queue = queue.Queue()
        self.cleanexit = False
        
        self.root.title(PROG_NAME)
        
        self.status_text = ""

        self.status_label = ttk.Label(
            self.root,
            text="Initializing..."
        )
        self.status_label.pack(pady=10)

        self.progress = ttk.Progressbar(
            self.root,
            mode="determinate",
            length=400
        )
        self.progress.pack(padx=20, pady=10)
        
        # Set geometry
        self.root.update_idletasks()
        current_geometry = self.root.winfo_toplevel().geometry()
        if (m := re.match(r"(\d+)x(\d+)\+(\d+)\+(\d+)", current_geometry)) is not None:
            width = int(m.group(1))
            height = int(m.group(2))
        else:
            width = 100
            height = 50
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        x = (screen_width - width) // 2
        y = ((screen_height - height) // 2) - 50
        self.root.geometry(f"{width}x{height}+{x}+{y}")

        self.root.after(100, self.poll_queue)

    def poll_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()

                # Update progress bar
                if msg["type"] == "progress":
                    self.update_progress(msg)
                # Successfully completes
                elif msg["type"] == "complete":
                    self.cleanexit = True
                    self.root.destroy()
                    return
                # Premature exit
                elif msg["type"] == "stop":
                    self.root.destroy()
                    return

        except queue.Empty:
            pass

        self.root.after(100, self.poll_queue)

    def update_progress(self, msg):
        # Update progress bar
        self.status_text = msg.get('status', self.status_text)

        self.progress["value"] = msg["percent"]

        self.status_label.config(
            text=self.status_text
        )
