# inputs_gui.py

import re
import platform
import shutil
import subprocess
import parsers
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .version_label import VersionLabel
from . import WINDOW_TITLE, WINDOW_HEIGHT, WINDOW_LENGTH
from ..toolbox import InputDictKeys, Scanners, validate_path_and_scanner, select_scanner


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
    def __init__(self, root: tk.Tk, inputs=None):
        if inputs is None:
            self.results = {}
        else:
            self.results = inputs
        self.results_project_name = ''
        self.results_project_version = ''
        self.cleanexit = False
        self.back = False
        self.dupe_detected_submit_again = False
        
        self.root = tk.Toplevel(root)
        self.root.title(WINDOW_TITLE)
        
        # Constant
        self.row_frame_pady = 4
        
        # Set geometry
        width = WINDOW_LENGTH
        height = WINDOW_HEIGHT
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        x = (screen_width - width) // 2
        y = ((screen_height - height) // 2) - 50
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        
        # Top row: Project Name + Version
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=(10, 0), padx=10, fill='x')

        tk.Label(top_frame, text="Project:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)

        self.project_name = PathInputWithPlaceholder(
            top_frame,
            placeholder="Project name",
            width=45
        )
        self.project_name.set_real_value(parsers.PROJ_NAME)
        self.project_name.pack(side=tk.LEFT, padx=5)

        tk.Label(top_frame, text="Version:", font=("Arial", 10)).pack(side=tk.LEFT, padx=(10, 5))

        self.project_version = PathInputWithPlaceholder(
            top_frame,
            placeholder="v1.0",
            width=30
        )
        self.project_version.set_real_value(parsers.PROJ_VERSION)
        self.project_version.pack(side=tk.LEFT, padx=5)

        # Make version visually smaller
        self.project_version.config(width=10)
        
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

        canvas.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")

        
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

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        back_button = tk.Button(button_frame, text="Go Back", command=self.go_back)
        back_button.pack(side=tk.LEFT, padx=(0, 10))

        submit_button = tk.Button(button_frame, text="Submit", command=self.submit_data)
        submit_button.pack(side=tk.LEFT)
        
        # Version text
        VersionLabel(self.root).pack(side=tk.BOTTOM, pady=5)

        # Execute GUI
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.root.attributes("-topmost", True)
        self.root.update()
        self.root.attributes("-topmost", False)
        
        root.wait_window(self.root)

    def add_entry(self, p_entry=None):
        row_frame = tk.Frame(self.entry_frame)
        row_frame.pack(fill='x', pady=self.row_frame_pady)
        
        if p_entry is None:
            entry = {}
        else:
            entry = p_entry

        # Move Up/Down
        up_btn = tk.Button(
            row_frame,
            text="↑",
            command=lambda: self.move_up(row_frame)
        )
        up_btn.pack(side=tk.LEFT, padx=2)

        down_btn = tk.Button(
            row_frame,
            text="↓",
            command=lambda: self.move_down(row_frame)
        )
        down_btn.pack(side=tk.LEFT, padx=2)

        # Scanner dropdown (Combobox)
        scanner_dropdown_placeholder = self._select_scanner(entry[InputDictKeys.SCANNER.value]) if len(entry) > 0 else 'Select Scanner...'
        scanners = Scanners.all_names()
        scanner_dropdown = ttk.Combobox(row_frame, values=scanners, width=max(len(i) for i in scanners)+3, state='readonly')
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

    def reorder(self):
        for frame, *_ in self.entries:
            frame.pack_forget()

        for frame, *_ in self.entries:
            frame.pack(fill='x', pady=self.row_frame_pady)
    
    def move_up(self, row_frame):
        index = next(
            i for i, (frame, *_)
            in enumerate(self.entries)
            if frame == row_frame
        )

        if index > 0:
            self.entries[index], self.entries[index - 1] = (
                self.entries[index - 1],
                self.entries[index]
            )
            self.reorder()
    
    def move_down(self, row_frame):
        index = next(
            i for i, (frame, *_)
            in enumerate(self.entries)
            if frame == row_frame
        )

        if index < len(self.entries) - 1:
            self.entries[index], self.entries[index + 1] = (
                self.entries[index + 1],
                self.entries[index]
            )
            self.reorder()

    def ask_open_filename(self, title, file_filters=None):
        if file_filters is None:
            file_filters = ''
        if platform.system() == "Linux" and shutil.which("zenity"):
            result = subprocess.run(
                ["zenity",
                 "--file-selection",
                 *( [file_filters] if len(file_filters) > 0 else [] ),
                 "--file-filter=All files | *",
                 ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return None

        return filedialog.askopenfilename(title=title)

    def browse_file(self, entry_widget, scanner):
        file_filters = None
        if scanner != 'Select Scanner...':
            selected_scanner = select_scanner(scanner)
            filter_str = ", ".join(f"*{ext}" for ext in selected_scanner.valid_ext)
            file_filters = f"--file-filter={selected_scanner.sname} files ({filter_str}) | {filter_str.replace(',', '')}"
        
        path = self.ask_open_filename(title="Select a file", file_filters=file_filters)
        if path is None:
            return
            
        if path:
            existing_paths = [e.get() for _, e, _, _ in self.entries if e != entry_widget]
            if path in existing_paths:
                messagebox.showwarning("Duplicate File", "This file path has already been selected.")
            entry_widget.set_real_value(path)
    
    def delete_entry(self, row_frame):
        for i, (frame, entry, version_dropdown, version_textbox) in enumerate(self.entries):
            if frame == row_frame:
                self.entries.pop(i)
                break
        row_frame.destroy()
    
    def go_back(self):
        self.back = True
        self.cleanexit = True
        self.root.destroy()
    
    def submit_data(self):
        results = []
        
        project_name = self.project_name.get().strip()
        project_version = self.project_version.get().strip()

        if project_name == "" or project_name == self.project_name.placeholder:
            project_name = ""
        
        if project_version == "" or project_version == self.project_version.placeholder:
            project_version = ""
        
        self.results_project_name = project_name
        self.results_project_version = project_version

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
        
        # Detect duplicate entries
        seen = set()
        for d in results:
            key = tuple(d[k] for k in d)

            if key in seen and not self.dupe_detected_submit_again:
                messagebox.showwarning("Invalid Input", "Duplicate input entries detected. If this is intentional, submit again.")
                self.dupe_detected_submit_again = True
                return

            seen.add(key)
        
        # Remove and Prepend keys must be carried over from self.results to results
        for result in self.results:
            for r in results:
                if (r[InputDictKeys.PATH.value] == result[InputDictKeys.PATH.value]
                    and r[InputDictKeys.SCANNER.value] == result[InputDictKeys.SCANNER.value]
                ):
                    if InputDictKeys.REMOVE.value in result:
                        r[InputDictKeys.REMOVE.value] = result[InputDictKeys.REMOVE.value]
                    if InputDictKeys.PREPEND.value in result:
                        r[InputDictKeys.PREPEND.value] = result[InputDictKeys.PREPEND.value]

        
        # Results successful, destroy window and exit
        self.results = results
        self.cleanexit = True
        self.root.destroy()
    
    def _select_scanner(self, scanner):
        # Wrapper that actually calls the select_scanner function in toolbox.py
        selected_scanner = select_scanner(scanner)
        if selected_scanner is None:
            return 'Select Scanner...'
        else:
            return selected_scanner.sname
