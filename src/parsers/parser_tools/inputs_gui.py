# gui.py

import os
import re
import parsers
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import PROG_NAME, VERSION
from .toolbox import InputDictKeys, validate_path_and_scanner, get_all_previews, generate_preview

# Constants
WINDOW_LENGTH = 900
WINDOW_HEIGHT = 500
WINDOW_TITLE = PROG_NAME

class YesNoGUI:
    def __init__(self, question="Do you want to continue?", windowsize=f"{WINDOW_LENGTH-400}x{WINDOW_HEIGHT-200}"):
        self.result = None
        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.geometry(windowsize)
        self.root.attributes('-topmost', True)
        self.root.update()
        self.root.attributes('-topmost', False)

        # Question label
        label = tk.Label(self.root, text=question, wraplength=280, font=("Arial", 12))
        label.pack(pady=15)

        # Buttons frame
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)

        yes_btn = tk.Button(btn_frame, text="Yes", width=10, command=self.yes)
        yes_btn.pack(side=tk.LEFT, padx=5)

        no_btn = tk.Button(btn_frame, text="No", width=10, command=self.no)
        no_btn.pack(side=tk.LEFT, padx=5)

        # Run GUI loop
        self.root.mainloop()

    def yes(self):
        self.result = True
        self.root.destroy()

    def no(self):
        self.result = False
        self.root.destroy()

class PathInputWithPlaceholder(tk.Entry):
    def __init__(self, master=None, placeholder="PLACEHOLDER", color='grey', **kwargs):
        super().__init__(master, **kwargs)

        self.placeholder = placeholder
        self.placeholder_color = color
        self.default_fg_color = self['fg']

        self.bind("<FocusIn>", self._clear_placeholder)
        self.bind("<FocusOut>", self._add_placeholder)

        self._add_placeholder()
    
    def set_real_value(self, value):
        if value is not None and len(value) > 0:
            self._clear_placeholder()
            self.delete(0, tk.END)
            self.insert(0, value)
            self['fg'] = self.default_fg_color

    def _clear_placeholder(self, event=None):
        if self.get() == self.placeholder and self['fg'] == self.placeholder_color:
            self.delete(0, tk.END)
        self['fg'] = self.default_fg_color

    def _add_placeholder(self, event=None):
        if not self.get():
            self.insert(0, self.placeholder)
            self['fg'] = self.placeholder_color

class InputsGUI:
    def __init__(self, inputs={}):
        self.results = inputs
        self.cleanexit = False
        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.geometry(f"{WINDOW_LENGTH}x{WINDOW_HEIGHT}")
        self.root.attributes('-topmost', True)
        self.root.update()
        self.root.attributes('-topmost', False)
        
        # Scrollable frame setup
        container = tk.Frame(self.root)
        container.pack(pady=10, padx=10, fill='both', expand=True)

        canvas = tk.Canvas(container)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)

        self.entry_frame = tk.Frame(canvas)

        # Attach the entry_frame inside the canvas
        entry_window = canvas.create_window((0, 0), window=self.entry_frame, anchor="nw")

        # When the frame is resized, update scrollregion
        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        # When the canvas is resized, match the frame width
        def on_canvas_configure(event):
            canvas.itemconfig(entry_window, width=event.width)

        self.entry_frame.bind("<Configure>", on_frame_configure)
        canvas.bind("<Configure>", on_canvas_configure)

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        
        # Entries setup
        self.entries = []

        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=5)

        add_button = tk.Button(control_frame, text="Add Input Entry", command=self.add_entry)
        add_button.pack(side=tk.LEFT, padx=5)
        
        if len(self.results) <= 0:
            self.add_entry()
        else:
            for entry in self.results:
                self.add_entry(entry)

        submit_button = tk.Button(self.root, text="Submit", command=self.submit_data)
        submit_button.pack(pady=10)
        
        # Version text
        version_label = tk.Label(self.root, text=f"{PROG_NAME} {VERSION}", font=("Arial", 8), fg="gray")
        version_label.pack(side="bottom", pady=5)

        # Execute GUI
        self.root.mainloop()

    def add_entry(self, entry={}):
        row_frame = tk.Frame(self.entry_frame)
        row_frame.pack(fill='x', pady=2)

        # Scanner dropdown (Combobox)
        scanner_dropdown_placeholder = self._select_scanner(entry[InputDictKeys.SCANNER.value]) if len(entry) > 0 else 'Select Scanner...'
        scanners = sorted(parsers.LIST_OF_SCANNERS, key=str.lower)
        scanner_dropdown = ttk.Combobox(row_frame, values=scanners, width=max([len(i) for i in scanners])+3, state='readonly')
        scanner_dropdown.set(scanner_dropdown_placeholder) # Set to current entry or placeholder
        scanner_dropdown.pack(side=tk.LEFT, padx=5)

        # For version text box
        if len(entry) > 0:
            if m := re.search(r"(v?\d+(?:\.\d+)+)", entry[InputDictKeys.SCANNER.value]):
                extracted_version = m.group(1)
            else: extracted_version = ''
        else: extracted_version = ''
        version_textbox = PathInputWithPlaceholder(row_frame, placeholder="Scanner Version")
        version_textbox.set_real_value(extracted_version)
        version_textbox.pack(side=tk.LEFT, padx=5)
        
        # Path to scanner input
        path_inp_entry = entry[InputDictKeys.PATH.value] if len(entry) > 0 else ''
        path_inp = PathInputWithPlaceholder(row_frame, placeholder="Select file path...")
        path_inp.pack(side=tk.LEFT, expand=True, fill='x', padx=5)
        path_inp.set_real_value(path_inp_entry)

        browse_btn = tk.Button(row_frame, text="Browse", command=lambda: self.browse_file(path_inp, scanner_dropdown.get().strip()))
        browse_btn.pack(side=tk.LEFT, padx=2)

        del_btn = tk.Button(row_frame, text="Delete", command=lambda: self.delete_entry(row_frame))
        del_btn.pack(side=tk.LEFT, padx=2)

        self.entries.append((row_frame, path_inp, scanner_dropdown, version_textbox))

    def browse_file(self, entry_widget, scanner):
        if scanner == 'Select Scanner...':
            messagebox.showinfo("Select a scanner", "Please select a scanner before browsing for a file.")
            return
        
        # If checkmarx, use askdirectory
        if scanner == 'Checkmarx':
            path = filedialog.askdirectory(title="Select a directory")
        # Else do regular
        else:
            path = filedialog.askopenfilename(title="Select a file")
            
        if path:
            existing_paths = [e.get() for _, e, _, _ in self.entries if e != entry_widget]
            if path in existing_paths:
                messagebox.showwarning("Duplicate File", "This file path has already been selected.")
                return
            entry_widget.set_real_value(path)
    
    def delete_entry(self, row_frame):
        for i, (frame, entry, version_dropdown, version_textbox) in enumerate(self.entries):
            if frame == row_frame:
                self.entries.pop(i)
                break
        row_frame.destroy()
    
    def submit_data(self):
        results = []
        runOnce = True

        for row_frame, path_entry, scanner_dropdown, version_entry in self.entries:
            path = path_entry.get().strip()
            scanner = scanner_dropdown.get().strip()
            version = version_entry.get().strip()

            # Validate inputs here
            
            # Check paths for existence and validity
            if path == "" or path == path_entry.placeholder:
                messagebox.showerror("Missing Path", "Please enter a valid file path.")
                return

            # Check if scanner is selected
            if scanner == "" or scanner == "Select Scanner...":
                messagebox.showerror("Missing Scanner", "Please select a scanner.")
                return
            
            rv = validate_path_and_scanner(path, scanner)
            if rv != "TRUE":
                messagebox.showerror("Invalid Input", rv)
                return
            
            # All checks pass

            # Check if version is defined, if so append to scanner
            if not (version == "" or version == version_entry.placeholder):
                scanner += ' ' + version
            
            results.append({
                InputDictKeys.PATH.value: path,
                InputDictKeys.SCANNER.value: scanner
            })
        
        # Results successful, destroy window and exit
        for result in results:
            for r in self.results:
                if result[InputDictKeys.PATH.value] == r[InputDictKeys.PATH.value]:
                    result[InputDictKeys.REMOVE.value] = r[InputDictKeys.REMOVE.value]
                    result[InputDictKeys.PREPEND.value] = r[InputDictKeys.PREPEND.value]
        
        self.results = results
        self.cleanexit = True
        self.root.destroy()
    
    def _select_scanner(self, scanner):
        scan_match = scanner.lower().replace(' ', '')
        if any(s in scan_match for s in parsers.aio_keywords):
            return 'AIO'
        elif any(s in scan_match for s in parsers.xmarx_keywords):
            return 'Checkmarx'
        elif any(s in scan_match for s in parsers.coverity_keywords):
            return 'Coverity'
        elif any(s in scan_match for s in parsers.cppcheck_keywords):
            return 'CPPCheck'
        elif any(s in scan_match for s in parsers.depcheck_keywords):
            return 'OWASP Dependency Check'
        elif any(s in scan_match for s in parsers.eslint_keywords):
            return 'ESLint'
        elif any(s in scan_match for s in parsers.fortify_keywords):
            return 'Fortify'
        elif any(s in scan_match for s in parsers.gnatsas_keywords):
            return 'GNAT SAS'
        elif any(s in scan_match for s in parsers.pragmatic_keywords):
            return 'Pragmatic'
        elif any(s in scan_match for s in parsers.pylint_keywords):
            return 'Pylint'
        elif any(s in scan_match for s in parsers.semgrep_keywords):
            return 'Semgrep'
        elif any(s in scan_match for s in parsers.sigasi_keywords):
            return 'Sigasi'
        elif any(s in scan_match for s in parsers.srm_keywords):
            return 'SRM'
        else:
            return 'Select Scanner...'


class AdjustPathsGUI:
    def __init__(self, current_inputs):
        self.results = {}
        self.cleanexit = False
        self.previous_results = current_inputs
        self.previews = get_all_previews(current_inputs)
        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.attributes('-topmost', True)
        self.root.update()
        self.root.attributes('-topmost', False)
        
        # Populate window
        #max_scanner_width = max([len(f"{i[InputDictKeys.SCANNER.value]} - {os.path.basename(i[InputDictKeys.PATH.value])}") for i in self.previous_results])

        self.root.geometry(f"{min(WINDOW_LENGTH+200, self.root.winfo_screenwidth())}x{WINDOW_HEIGHT}")
        
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
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
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

        # Add path editing row
        for idx, item in enumerate(self.previous_results, start=1):
            path = item.get(InputDictKeys.PATH.value, "")
            scanner = item.get(InputDictKeys.SCANNER.value, "")
            remove = item.get(InputDictKeys.REMOVE.value, "")
            prepend = item.get(InputDictKeys.PREPEND.value, "")

            remove_var = tk.StringVar()
            add_var = tk.StringVar()

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

            # Live update function
            def update_preview(var1, var2, p, box):
                r = generate_preview(self.previews[p], var1.get(), var2.get())
                box.config(state='normal')
                box.delete(0, tk.END)
                box.insert(0, r)
                box.config(state='readonly')

            remove_var.trace_add('write', lambda *args, v1=remove_var, v2=add_var, p=path, b=preview_box: update_preview(v1, v2, p, b))
            add_var.trace_add('write', lambda *args, v1=remove_var, v2=add_var, p=path, b=preview_box: update_preview(v1, v2, p, b))


            self.path_entries.append((scanner, path, remove_var, add_var, preview_box))

        # Button to finalize or do further actions
        tk.Button(self.root, text="Save Adjusted Paths", command=self.collect_paths).pack(pady=10)
        
        # Version text
        version_label = tk.Label(self.root, text=f"{PROG_NAME} {VERSION}", font=("Arial", 8), fg="gray")
        version_label.pack(side="bottom", pady=5)

        self.root.mainloop()

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

class OutfileFlagsGUI:
    def __init__(self, outfile="", control_flags={}):
        self.initial_outfile = outfile
        self.initial_flags = control_flags
        self.results = {}
        self.cleanexit = False
        
        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.geometry(f"{500}x{300}")
        self.root.attributes('-topmost', True)
        self.root.update()
        self.root.attributes('-topmost', False)

        self.output_path = tk.StringVar()

        # ─── File Path Selector ─────────────────────────────
        path_frame = tk.Frame(self.root)
        path_frame.pack(pady=15, padx=10, fill="x")

        tk.Label(path_frame, text="Select Output File:", anchor="w").pack(anchor="w")

        path_entry = tk.Entry(path_frame, textvariable=self.output_path)
        path_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        path_entry.delete(0, tk.END)
        path_entry.insert(0, self.initial_outfile)

        browse_btn = tk.Button(path_frame, text="Browse", command=self.browse_file)
        browse_btn.pack(side="left")

        # ─── Checkboxes for Flags ─────────────────────────────
        mapping_val = self.initial_flags.get(InputDictKeys.OVERRIDE_VULN_MAPPING.value, True)
        cwe_val = self.initial_flags.get(InputDictKeys.OVERRIDE_CWE.value, True)
        confidence_val = self.initial_flags.get(InputDictKeys.OVERRIDE_CONFIDENCE.value, True)
        self.enable_category_mapping = tk.BooleanVar(value=mapping_val)
        self.enable_override_cwe = tk.BooleanVar(value=cwe_val)
        self.enable_override_confidence = tk.BooleanVar(value=confidence_val)

        checkbox_frame = tk.LabelFrame(self.root, text="Output Flags", padx=10, pady=10)
        checkbox_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.add_checkbox_with_tooltip(
            checkbox_frame,
            "Enable CWE Category Mappings",
            self.enable_category_mapping,
            "If enabled, this will append \":CATEGORY\", \":DISCOURAGED\", etc. to the end of CWE numbers."
        )
        
        self.add_checkbox_with_tooltip(
            checkbox_frame,
            "Enable Override CWE",
            self.enable_override_cwe,
            "If enabled, this will change the scanner's CWE value to a user-specified value for findings of specific types."
        )

        self.add_checkbox_with_tooltip(
            checkbox_frame,
            "Enable Override Confidence",
            self.enable_override_confidence,
            "If enabled, this will change the confidence value to a user-specified one for findings of specific types."
        )

        # ─── Submit Button ─────────────────────────────
        submit_btn = tk.Button(self.root, text="Submit", command=self.submit)
        submit_btn.pack(pady=10)
        
        # Version text
        version_label = tk.Label(self.root, text=f"{PROG_NAME} {VERSION}", font=("Arial", 8), fg="gray")
        version_label.pack(side="bottom", pady=5)

        self.root.mainloop()

    def browse_file(self):
        file_path = filedialog.asksaveasfilename(
            title="Select Output File",
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx"), ("CSV Files", "*.csv")]
        )
        if file_path:
            self.output_path.set(file_path)
    
    def add_checkbox_with_tooltip(self, parent, text, variable, tooltip_text):
        frame = tk.Frame(parent)
        frame.pack(anchor="w", pady=2, fill="x")

        cb = tk.Checkbutton(frame, text=text, variable=variable)
        cb.pack(side="left")

        q_label = tk.Label(frame, text="?", fg="blue", font=("Arial", 10, "bold"), cursor="question_arrow")
        q_label.pack(side="left", padx=5)

        ToolTip(q_label, tooltip_text)

    def submit(self):
        output_path = self.output_path.get().strip()
        ext = os.path.splitext(output_path.lower())[1]
        
        if ext not in ['.xlsx', '.csv']:
            messagebox.showerror("Invalid File", "The output file must be an .xlsx or .csv file.")
            return

        self.results = {
            InputDictKeys.OUTFILE.value: output_path,
            InputDictKeys.OVERRIDE_VULN_MAPPING.value: self.enable_category_mapping.get(),
            InputDictKeys.OVERRIDE_CWE.value: self.enable_override_cwe.get(),
            InputDictKeys.OVERRIDE_CONFIDENCE.value: self.enable_override_confidence.get()
        }

        self.cleanexit = True
        self.root.destroy()
    


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        x, y, _, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + cy + 25
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)  # Remove window decorations
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, background="lightyellow",
                         relief="solid", borderwidth=1, padx=5, pady=3,
                         font=("Arial", 9))
        label.pack()

    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

def message_box(title, msg, type):
    if type == 'error':
        messagebox.showerror(title, msg)
    elif type == 'warning':
        messagebox.showwarning(title, msg)
    elif type == 'info':
        messagebox.showinfo(title, msg)