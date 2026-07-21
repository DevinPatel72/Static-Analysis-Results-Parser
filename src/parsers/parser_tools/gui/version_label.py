# version_label.py

import tkinter as tk
from tkinter import messagebox
import parsers

class VersionLabel(tk.Label):
    def __init__(self, parent, **kwargs):
        self.prog_name = parsers.PROG_NAME
        self.version = parsers.VERSION

        super().__init__(
            parent,
            text=f"{self.prog_name} {self.version}",
            font=("Arial", 8),
            fg="gray",
            cursor="hand2",
            **kwargs
        )

        self.bind("<Button-1>", self.show_about)
        self.bind("<Enter>", self.hover)
        self.bind("<Leave>", self.unhover)

    def hover(self, event):
        self.config(fg="blue")

    def unhover(self, event):
        self.config(fg="gray")

    def show_about(self, event=None):
        messagebox.showinfo(
            "About",
            f"{self.prog_name}\n\n"
            f"Version: {self.version}\n\n"
            "Copyright (c) 2026 Devin Patel\n\n"
            "Licensed under the Apache License, Version 2.0."
        )