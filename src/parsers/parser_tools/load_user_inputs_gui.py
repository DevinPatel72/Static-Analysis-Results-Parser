# load_user_inputs_gui.py

import os
import json
import parsers
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkfont

from .. import PROG_NAME, VERSION
from .toolbox import InputDictKeys, InputSchemaKeys, InputConfigFlags

class JsonInputPreviewGUI:
    def __init__(self):
        self.cleanexit = False
        self.results = None
        self.execute_now = False
        self.json_folder = parsers.INPUTS_DIR
        self.project_files = {}
        self.scanner_sections = []

        self.current_wraplength = 0
        self._tooltip = None
        self._tooltip_after_id = None

        self.root = tk.Tk()
        self.root.title(PROG_NAME)
        self.root.geometry("1300x500")
        
        self.root.protocol(
            "WM_DELETE_WINDOW",
            self._on_close
        )

        self.root.attributes("-topmost", True)
        self.root.update()
        self.root.attributes("-topmost", False)
        
        self.selected_file_var = tk.StringVar(value="")

        self._build_gui()
        self._load_json_files()

        self.root.mainloop()

    def _on_close(self):
        self.cleanexit = False
        self.results = None
        self.root.destroy()

    def _build_gui(self):
        
        # Version text
        version_label = tk.Label(self.root, text=f"{PROG_NAME} {VERSION}", font=("Arial", 8), fg="gray")
        version_label.pack(side=tk.BOTTOM, pady=5)
        
        # Submit buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(
            side=tk.BOTTOM,
            fill=tk.X,
            padx=10,
            pady=10
        )

        self.load_button = ttk.Button(
            button_frame,
            text="Load",
            command=self._submit
        )

        self.submit_button = ttk.Button(
            button_frame,
            text="Load",
            command=self._submit
        )
        self.submit_button.pack(side=tk.RIGHT)

        self.submit_execute_button = ttk.Button(
            button_frame,
            text="Execute",
            command=self._execute
        )
        
        # Pack only if something is selected
        self._set_execute_button_visible(False)

        
        container = ttk.Frame(
            self.root,
            padding=10
        )
        self.section_header_font = tkfont.Font(
            family="Arial",
            size=12,
            weight="bold"
        )

        self.scanner_header_font = tkfont.Font(
            family="Arial",
            size=10,
            weight="bold"
        )
        container.pack(
            fill=tk.BOTH,
            expand=True
        )
        # =====================================================
        # Left Panel - File List
        # =====================================================

        self.left_frame = ttk.Frame(container)
        self.left_frame.pack(
            side=tk.LEFT,
            fill=tk.Y,
            padx=(0, 10)
        )
        self.left_frame.pack_propagate(False)

        ttk.Label(
            self.left_frame,
            text="Input Profiles",
            font=self.section_header_font
        ).pack(anchor="w")

        self.selected_file_var = tk.StringVar(value="")

        self.file_selection_canvas = tk.Canvas(
            self.left_frame,
            highlightthickness=0
        )

        scrollbar = ttk.Scrollbar(
            self.left_frame,
            orient=tk.VERTICAL,
            command=self.file_selection_canvas.yview
        )

        self.file_selection_frame = ttk.Frame(
            self.file_selection_canvas
        )

        self.file_selection_frame.bind(
            "<Configure>",
            lambda e: self.file_selection_canvas.configure(
                scrollregion=self.file_selection_canvas.bbox("all")
            )
        )

        self.file_selection_canvas.create_window(
            (0, 0),
            window=self.file_selection_frame,
            anchor="nw"
        )

        self.file_selection_canvas.configure(
            yscrollcommand=scrollbar.set
        )

        self.file_selection_canvas.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )

        # =====================================================
        # Right Panel - Preview
        # =====================================================

        right_frame = ttk.Frame(container)

        right_frame.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        tk.Label(
            right_frame,
            text="Preview",
            font=self.section_header_font
        ).pack(anchor="w")

        self.controls_frame = ttk.Frame(right_frame)

        ttk.Button(
            self.controls_frame,
            text="Expand All",
            command=self._expand_all
        ).pack(
            side=tk.LEFT,
            padx=(0, 5)
        )

        ttk.Button(
            self.controls_frame,
            text="Collapse All",
            command=self._collapse_all
        ).pack(
            side=tk.LEFT
        )
        
        for child in self.controls_frame.winfo_children():
            try:
                child.configure(width=12)
            except:
                pass

        self.preview_canvas = tk.Canvas(
            right_frame,
            highlightthickness=0
        )
        self.preview_canvas.bind(
            "<Configure>",
            self._update_wraplengths
        )

        preview_scrollbar = ttk.Scrollbar(
            right_frame,
            orient=tk.VERTICAL,
            command=self.preview_canvas.yview
        )

        self.preview_content = ttk.Frame(
            self.preview_canvas
        )

        self.preview_content.bind(
            "<Configure>",
            lambda e: self.preview_canvas.configure(
                scrollregion=self.preview_canvas.bbox("all")
            )
        )

        self.preview_canvas.create_window(
            (0, 0),
            window=self.preview_content,
            anchor="nw"
        )

        self.preview_canvas.configure(
            yscrollcommand=preview_scrollbar.set
        )

        self.preview_canvas.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        preview_scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )

        # Mouse wheel support

        self.root.bind_all(
            "<MouseWheel>",
            self._on_mousewheel
        )

        self.root.bind_all(
            "<Button-4>",
            lambda e: self.preview_canvas.yview_scroll(-1, "units")
        )

        self.root.bind_all(
            "<Button-5>",
            lambda e: self.preview_canvas.yview_scroll(1, "units")
        )
    
    def _set_execute_button_visible(self, visible: bool):
        if visible:
            if not self.submit_execute_button.winfo_manager():
                self.submit_execute_button.pack(
                    side=tk.RIGHT,
                    padx=(0, 5)
                )
        else:
            if self.submit_execute_button.winfo_manager():
                self.submit_execute_button.pack_forget()
    
    def _submit(self):
        self.results = self.selected_file_var.get()
        self.cleanexit = True
        self.root.destroy()
    
    def _execute(self):
        self.execute_now = True
        self._submit()

    def _update_wraplengths(self, event):
        self.current_wraplength = max(
            400,
            event.width - 250
        )

    def _on_mousewheel(self, event):
        self.preview_canvas.yview_scroll(
            int(-1 * (event.delta / 120)),
            "units"
        )

    def _load_json_files(self):
        self.project_files.clear()
        file_list = sorted(os.listdir(self.json_folder))

        for child in self.file_selection_frame.winfo_children():
            child.destroy()

        if not os.path.isdir(self.json_folder):
            return
        
        font = tkfont.nametofont("TkDefaultFont")

        max_width = max(
            (
                font.measure(name)
                for name in file_list
            ),
            default=150
        )
        
        desired_width = min(
            max(
                150,
                max_width + 40
            ),
            350
        )

        self.left_frame.configure(
            width=desired_width
        )
        
        # Blank file
        radio = ttk.Radiobutton(
            self.file_selection_frame,
            text="<New Project>",
            variable=self.selected_file_var,
            value="",
            command=lambda fp="": self._load_preview_from_path(fp)
        )

        radio.pack(
            anchor="w",
            fill=tk.X,
            padx=2,
            pady=1
        )

        # SARP inputs files
        for filename in file_list:
            if not filename.lower().endswith(".json"):
                continue

            full_path = os.path.join(
                self.json_folder,
                filename
            )

            self.project_files[
                filename
            ] = full_path

            radio = ttk.Radiobutton(
                self.file_selection_frame,
                text=filename,
                variable=self.selected_file_var,
                value=full_path,
                command=lambda fp=full_path: self._load_preview_from_path(fp)
            )

            radio.pack(
                anchor="w",
                fill=tk.X,
                padx=2,
                pady=1
            )
    
    def _load_preview_from_path(self, filepath):
        self._set_execute_button_visible(bool(filepath))
        try:
            if len(filepath) > 0:
                with open(
                    filepath,
                    "r",
                    encoding="utf-8-sig"
                ) as fp:
                    data = json.load(fp)

                self._populate_preview(data)
            else:
                self._populate_preview(None)

        except Exception as ex:
            self.controls_frame.pack_forget()
            self.scanner_sections.clear()

            for child in self.preview_content.winfo_children():
                child.destroy()

            ttk.Label(
                self.preview_content,
                text=f"Failed to load JSON file:\n\n{ex}"
            ).pack(anchor="w")

    def _create_scanner_section(
        self,
        parent,
        scanner_data
    ):
        scanner_name = scanner_data.get(
            InputDictKeys.SCANNER.value,
            "Unknown Scanner"
        )

        section_frame = ttk.Frame(parent)

        section_frame.pack(
            fill=tk.X,
            pady=(2, 4),
            anchor="w"
        )

        expanded = tk.BooleanVar(
            value=False
        )

        body_frame = ttk.Frame(
            section_frame
        )

        header_font = self.scanner_header_font

        header_label = tk.Label(
            section_frame,
            text=f"▶ {scanner_name}",
            font=header_font,
            cursor="hand2",
            anchor="w"
        )

        header_label.pack(
            fill=tk.X,
            anchor="w"
        )

        def toggle(event=None):
            if expanded.get():
                expanded.set(False)

                body_frame.pack_forget()

                header_label.config(
                    text=f"▶ {scanner_name}"
                )
            else:
                expanded.set(True)

                body_frame.pack(
                    fill=tk.X,
                    padx=25
                )

                header_label.config(
                    text=f"▼ {scanner_name}"
                )

        header_label.bind(
            "<Button-1>",
            toggle
        )

        fields = [
            (
                "File Path",
                scanner_data.get(
                    InputDictKeys.PATH.value,
                    ""
                )
            ),
            (
                "Remove Path",
                scanner_data.get(
                    InputDictKeys.REMOVE.value,
                    ""
                )
            ),
            (
                "Prepend Path",
                scanner_data.get(
                    InputDictKeys.PREPEND.value,
                    ""
                )
            ),
        ]

        for label_text, value in fields:
            row = ttk.Frame(body_frame)

            row.pack(
                fill=tk.X,
                anchor="w"
            )

            ttk.Label(
                row,
                text=f"{label_text}:",
                width=15
            ).pack(
                side=tk.LEFT
            )

            self._create_copyable_label(
                row,
                value,
                wraplength=getattr(
                            self,
                            "current_wraplength",
                            700
                        )
            ).pack(
                side=tk.LEFT,
                fill=tk.X,
                expand=True
            )

        self.scanner_sections.append(
            {
                "expanded": expanded,
                "body": body_frame,
                "header": header_label,
                "name": scanner_name
            }
        )

    def _expand_all(self):
        for section in self.scanner_sections:
            if not section["expanded"].get():
                section["expanded"].set(True)

                section["body"].pack(
                    fill=tk.X,
                    padx=25
                )

            section["header"].config(
                text=f"▼ {section['name']}"
            )

    def _collapse_all(self):
        for section in self.scanner_sections:
            section["expanded"].set(False)

            section["body"].pack_forget()

            section["header"].config(
                text=f"▶ {section['name']}"
            )

    def _populate_preview(
        self,
        data
    ):
        if not self.controls_frame.winfo_ismapped():
            self.controls_frame.pack(
                fill=tk.X,
                pady=(0, 5)
            )
        
        self.scanner_sections.clear()

        for child in self.preview_content.winfo_children():
            child.destroy()
            
        if data is None:
            return

        row = ttk.Frame(self.preview_content)
        row.pack(anchor="w", fill=tk.X)

        ttk.Label(
            row,
            text="Project Name:"
        ).pack(side=tk.LEFT)

        self._create_copyable_label(
            row,
            data.get(
                InputSchemaKeys.PROJ_NAME.value,
                "<missing>"
            )
        ).pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True
        )

        row = ttk.Frame(self.preview_content)
        row.pack(anchor="w", fill=tk.X)

        ttk.Label(
            row,
            text="Project Version:"
        ).pack(side=tk.LEFT)

        self._create_copyable_label(
            row,
            data.get(
                InputSchemaKeys.PROJ_VERSION.value,
                "<missing>"
            )
        ).pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True
        )

        ttk.Separator(
            self.preview_content,
            orient=tk.HORIZONTAL
        ).pack(
            fill=tk.X,
            pady=5
        )

        tk.Label(
            self.preview_content,
            text="Scanner Inputs",
            font=self.section_header_font
        ).pack(
            anchor="w"
        )

        scanner_inputs = data.get(
            InputSchemaKeys.MAIN.value,
            []
        )

        if not scanner_inputs:
            ttk.Label(
                self.preview_content,
                text="No scanner inputs defined."
            ).pack(
                anchor="w",
                padx=10
            )
        else:
            for scanner in scanner_inputs:
                self._create_scanner_section(
                    self.preview_content,
                    scanner
                )

        ttk.Separator(
            self.preview_content,
            orient=tk.HORIZONTAL
        ).pack(
            fill=tk.X,
            pady=5
        )

        row = ttk.Frame(self.preview_content)

        row.pack(
            anchor="w",
            fill=tk.X,
            pady=5
        )

        tk.Label(
            row,
            text="Output File:",
            font=self.section_header_font
        ).pack(side=tk.LEFT)

        self._create_copyable_label(
            row,
            data.get(
                InputSchemaKeys.OUTFILE.value,
                "<missing>"
            ),
            wraplength=getattr(
                            self,
                            "current_wraplength",
                            700
                        )
        ).pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True
        )

        ttk.Separator(
            self.preview_content,
            orient=tk.HORIZONTAL
        ).pack(
            fill=tk.X,
            pady=5
        )

        tk.Label(
            self.preview_content,
            text="Flags",
            font=self.section_header_font
        )

        flags = data.get(
            InputSchemaKeys.FLAGS.value,
            {}
        )

        for f in InputConfigFlags:
            value = bool(
                flags.get(
                    f.flag,
                    False
                )
            )

            row = ttk.Frame(
                self.preview_content
            )

            row.pack(
                anchor="w",
                padx=10
            )

            ttk.Label(
                row,
                text=f"{f.flag}: "
            ).pack(
                side=tk.LEFT
            )

            tk.Label(
                row,
                text=str(value),
                fg="blue" if value else "red"
            ).pack(
                side=tk.LEFT
            )

    def _show_tooltip(self, widget, text):
        if hasattr(self, "_tooltip") and self._tooltip:
            self._tooltip.destroy()

        self._tooltip = tk.Toplevel(widget)
        self._tooltip.wm_overrideredirect(True)

        x = widget.winfo_rootx() + 15
        y = widget.winfo_rooty() + widget.winfo_height() + 5

        self._tooltip.geometry(f"+{x}+{y}")

        tk.Label(
            self._tooltip,
            text=text,
            bg="#ffffe0",
            relief="solid",
            borderwidth=1,
            padx=5,
            pady=2
        ).pack()

    def _hide_tooltip(self, event=None):
        if hasattr(self, "_tooltip") and self._tooltip:
            self._tooltip.destroy()
            self._tooltip = None
    
    def _schedule_tooltip(self, widget, text):
        self._tooltip_after_id = self.root.after(
            300,
            lambda: self._show_tooltip(widget, text)
        )

    def _cancel_tooltip(self, event=None):
        if hasattr(self, "_tooltip_after_id") and self._tooltip_after_id:
            self.root.after_cancel(self._tooltip_after_id)
            self._tooltip_after_id = None

        self._hide_tooltip()

    def _copy_to_clipboard(self, value, label=None):
        self.root.clipboard_clear()
        self.root.clipboard_append(str(value))
        self.root.update()
        if label:
            original_text = label.cget("text")
            original_fg = label.cget("fg")

            label.config(
                text=value,
                fg="blue"
            )

            self.root.after(
                100,
                lambda: label.config(
                    text=original_text,
                    fg=original_fg
                )
            )

    def _create_copyable_label(
        self,
        parent,
        text,
        wraplength=700
    ):
        label = tk.Label(
            parent,
            text=str(text),
            fg="black",
            cursor="hand2",
            justify="left",
            anchor="w",
            wraplength=wraplength
        )

        label.bind(
            "<Button-1>",
            lambda e, v=text: self._copy_to_clipboard(v, label)
        )

        label.bind(
            "<Enter>",
            lambda e: self._schedule_tooltip(
                label,
                "Click to copy to clipboard"
            )
        )

        label.bind(
            "<Leave>",
            self._cancel_tooltip
        )

        return label
