# load_user_inputs_gui.py

import os
import json
import parsers
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkfont

from .. import PROG_NAME, VERSION
from .toolbox import InputDictKeys, InputSchemaKeys

class JsonInputPreviewGUI:
    def __init__(self):
        self.cleanexit = False
        self.results = None
        self.json_folder = parsers.INPUTS_DIR
        self.project_files = {}
        self.scanner_sections = []

        self.root = tk.Tk()
        self.root.title(PROG_NAME)
        self.root.geometry("1300x500")

        self.root.attributes("-topmost", True)
        self.root.update()
        self.root.attributes("-topmost", False)

        self._build_gui()
        self._load_json_files()

        self.root.mainloop()

    def _build_gui(self):
        
        # Version text
        version_label = tk.Label(self.root, text=f"{PROG_NAME} {VERSION}", font=("Arial", 8), fg="gray")
        version_label.pack(side="bottom", pady=5)
        
        container = ttk.Frame(
            self.root,
            padding=10
        )
        container.pack(
            fill=tk.BOTH,
            expand=True
        )
        # =====================================================
        # Left Panel - File List
        # =====================================================

        left_frame = ttk.Frame(container)

        left_frame.pack(
            side=tk.LEFT,
            fill=tk.Y,
            padx=(0, 10)
        )

        ttk.Label(
            left_frame,
            text="User Inputs"
        ).pack(anchor="w")

        self.file_tree = ttk.Treeview(
            left_frame,
            columns=(),
            show="tree",
            height=30
        )

        self.file_tree.pack(
            fill=tk.Y,
            expand=True
        )

        self.file_tree.bind(
            "<<TreeviewSelect>>",
            self._on_file_selected
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

        ttk.Label(
            right_frame,
            text="Preview"
        ).pack(
            anchor="w"
        )

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

        self.preview_canvas = tk.Canvas(
            right_frame,
            highlightthickness=0
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

        self.preview_canvas.bind(
            "<Enter>",
            lambda e: self.preview_canvas.bind_all(
                "<MouseWheel>",
                self._on_mousewheel
            )
        )

        self.preview_canvas.bind(
            "<Leave>",
            lambda e: self.preview_canvas.unbind_all(
                "<MouseWheel>"
            )
        )

        self.preview_canvas.bind(
            "<Button-4>",
            lambda e: self.preview_canvas.yview_scroll(
                -1,
                "units"
            )
        )

        self.preview_canvas.bind(
            "<Button-5>",
            lambda e: self.preview_canvas.yview_scroll(
                1,
                "units"
            )
        )


    def _on_mousewheel(self, event):
        self.preview_canvas.yview_scroll(
            int(-1 * (event.delta / 120)),
            "units"
        )

    def _load_json_files(self):
        self.project_files.clear()

        for item in self.file_tree.get_children():
            self.file_tree.delete(item)

        if not os.path.isdir(self.json_folder):
            return

        for filename in sorted(
            os.listdir(self.json_folder)
        ):
            if not filename.lower().endswith(
                ".json"
            ):
                continue

            full_path = os.path.join(
                self.json_folder,
                filename
            )

            self.project_files[
                filename
            ] = full_path

            self.file_tree.insert(
                "",
                tk.END,
                iid=filename,
                text=filename
            )

    def _on_file_selected(self, event):
        selection = self.file_tree.selection()

        if not selection:
            return

        filename = selection[0]
        filepath = self.project_files[filename]

        try:
            with open(
                filepath,
                "r",
                encoding="utf-8-sig"
            ) as fp:
                data = json.load(fp)

            self._populate_preview(data)

        except Exception as ex:
            self.controls_frame.pack_forget()
            self.scanner_sections.clear()

            for child in self.preview_content.winfo_children():
                child.destroy()

            ttk.Label(
                self.preview_content,
                text=(
                    "Failed to load JSON file:\n\n"
                    f"{ex}"
                )
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

        header_font = tkfont.Font(
            weight="bold"
        )

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

            ttk.Label(
                row,
                text=str(value)
            ).pack(
                side=tk.LEFT
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

        ttk.Label(
            self.preview_content,
            text=(
                f"Project Name: "
                f"{data.get(InputSchemaKeys.PROJ_NAME.value, '<missing>')}"
            )
        ).pack(
            anchor="w",
            pady=(0, 2)
        )

        ttk.Label(
            self.preview_content,
            text=(
                f"Project Version: "
                f"{data.get(InputSchemaKeys.PROJ_VERSION.value, '<missing>')}"
            )
        ).pack(
            anchor="w",
            pady=(0, 10)
        )

        ttk.Separator(
            self.preview_content,
            orient=tk.HORIZONTAL
        ).pack(
            fill=tk.X,
            pady=5
        )

        ttk.Label(
            self.preview_content,
            text="Scanner Inputs"
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

        ttk.Label(
            self.preview_content,
            text=(
                f"Output File: "
                f"{data.get(InputSchemaKeys.OUTFILE.value, '<missing>')}"
            )
        ).pack(
            anchor="w",
            pady=5
        )

        ttk.Separator(
            self.preview_content,
            orient=tk.HORIZONTAL
        ).pack(
            fill=tk.X,
            pady=5
        )

        ttk.Label(
            self.preview_content,
            text="Flags"
        ).pack(
            anchor="w"
        )

        flags = data.get(
            InputSchemaKeys.FLAGS.value,
            {}
        )

        for flag_name in InputDictKeys.FLAGS.value:
            value = bool(
                flags.get(
                    flag_name,
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
                text=f"{flag_name}: "
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

    def get_selected_file(self):
        selection = self.file_tree.selection()

        if not selection:
            return None

        filename = selection[0]

        return self.project_files.get(
            filename
        )

