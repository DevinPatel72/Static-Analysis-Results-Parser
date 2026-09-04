# adjust_paths_gui.py

import os
import tkinter as tk

from .version_label import VersionLabel
from . import WINDOW_TITLE, WINDOW_HEIGHT, WINDOW_LENGTH
from ..toolbox import InputDictKeys, get_all_previews, generate_preview


class AdjustPathsGUI:
    def __init__(self, root: tk.Tk, current_inputs):
        self.results = {}
        self.cleanexit = False
        self.back = False
        self.root = tk.Toplevel(root)
        self.root.title(WINDOW_TITLE)
        
        # Get previews
        self.previous_results = current_inputs
        self.previews = get_all_previews(current_inputs)
        
        
        # Set geometry
        width = min(WINDOW_LENGTH+200, self.root.winfo_screenwidth())
        height = WINDOW_HEIGHT
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        x = (screen_width - width) // 2
        y = ((screen_height - height) // 2) - 50
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        self.updated_paths = []

        # Scrollable area
        container = tk.Frame(self.root)
        container.pack(fill='both', expand=True, padx=10, pady=10)

        canvas = tk.Canvas(container)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)

        table_frame = tk.Frame(canvas)
        table_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        inner_window = canvas.create_window((0, 0), window=table_frame, anchor="nw")

        def on_canvas_configure(event):
            canvas.itemconfig(inner_window, width=event.width)

        canvas.bind("<Configure>", on_canvas_configure)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        
        self.path_entries = []
        
        # ─── Add Header Row ─────────────────────────────
        table_frame = tk.Frame(table_frame)
        table_frame.pack(fill='x', pady=(0, 5))

        tk.Label(table_frame, text="Scanner", font=("Arial", 10, "bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=5)
        tk.Label(table_frame, text="Substring to Remove", font=("Arial", 10, "bold"), anchor="w").grid(row=0, column=1, sticky="ew", padx=5)
        tk.Label(table_frame, text="Substring to Prepend", font=("Arial", 10, "bold"), anchor="w").grid(row=0, column=2, sticky="ew", padx=5)
        tk.Label(table_frame, text="Preview", font=("Arial", 10, "bold"), anchor="w").grid(row=0, column=3, sticky="ew", padx=5)

        table_frame.grid_columnconfigure(1, weight=1)
        table_frame.grid_columnconfigure(2, weight=1)
        table_frame.grid_columnconfigure(3, weight=1)
        
        # Live update function
        def update_preview(var1, var2, p, box):
            r = generate_preview(self.previews[p], var1.get(), var2.get())
            box.config(state='normal')
            box.delete(0, tk.END)
            box.insert(0, r)
            box.config(state='readonly')

        # Add path editing row
        for idx, item in enumerate(self.previous_results, start=1):
            path = item.get(InputDictKeys.PATH.value, "")
            scanner = item.get(InputDictKeys.SCANNER.value, "")
            remove = item.get(InputDictKeys.REMOVE.value, "")
            prepend = item.get(InputDictKeys.PREPEND.value, "")

            remove_var = tk.StringVar(master=self.root)
            add_var = tk.StringVar(master=self.root)

            remove_entry = tk.Entry(table_frame, textvariable=remove_var)
            remove_entry.delete(0, tk.END)
            remove_entry.insert(0, remove)
            add_entry = tk.Entry(table_frame, textvariable=add_var)
            add_entry.delete(0, tk.END)
            add_entry.insert(0, prepend)

            preview_box = tk.Entry(table_frame, state='normal', readonlybackground="#f0f0f0")
            preview_box.insert(0, generate_preview(self.previews[path], remove, prepend))
            preview_box.config(state='readonly')

            # Place them in grid
            tk.Label(table_frame, text=f"{scanner} - {os.path.basename(path)}", anchor="w").grid(row=idx, column=0, sticky="w", padx=5, pady=5)
            remove_entry.grid(row=idx, column=1, sticky="ew", padx=5, pady=5)
            add_entry.grid(row=idx, column=2, sticky="ew", padx=5, pady=5)
            preview_box.grid(row=idx, column=3, sticky="ew", padx=5, pady=5)

            table_frame.grid_columnconfigure(1, weight=1)
            table_frame.grid_columnconfigure(2, weight=1)
            table_frame.grid_columnconfigure(3, weight=1)

            remove_var.trace_add('write', lambda *args, v1=remove_var, v2=add_var, p=path, b=preview_box: update_preview(v1, v2, p, b))
            add_var.trace_add('write', lambda *args, v1=remove_var, v2=add_var, p=path, b=preview_box: update_preview(v1, v2, p, b))


            self.path_entries.append((scanner, path, remove_var, add_var, preview_box))

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        back_button = tk.Button(button_frame, text="Go Back", command=self.go_back)
        back_button.pack(side=tk.LEFT, padx=(0, 10))

        submit_button = tk.Button(button_frame, text="Save Adjusted Paths", command=self.collect_paths)
        submit_button.pack(side=tk.LEFT)
        
        # Version text
        VersionLabel(self.root).pack(side=tk.BOTTOM, pady=5)

        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.root.attributes("-topmost", True)
        self.root.update()
        self.root.attributes("-topmost", False)

        root.wait_window(self.root)
    
    def go_back(self):
        self.back = True
        self.cleanexit = True
        self.root.destroy()

    def collect_paths(self):
        self.results = []

        for scanner, original_path, remove_var, add_var, _ in self.path_entries:
            remove_val = remove_var.get().strip()
            add_val = add_var.get().strip()
            self.results.append({
                InputDictKeys.SCANNER.value: scanner,
                InputDictKeys.PATH.value: original_path,
                InputDictKeys.REMOVE.value: remove_val,
                InputDictKeys.PREPEND.value: add_val
            })
        
        
        self.cleanexit = True
        self.root.destroy()