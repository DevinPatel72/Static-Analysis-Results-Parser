# outfile_flags_gui.py

import os
import platform
import shutil
import subprocess
import parsers
import tkinter as tk
from tkinter import filedialog, messagebox

from .version_label import VersionLabel
from .tooltip import ToolTip
from . import WINDOW_TITLE, FORMAT_MAP, EXT_TO_FORMAT, create_tk_variable
from ..toolbox import GuiWindow, InputDictKeys, InputConfigFlags, InputAdditionalOptions


class OutfileFlagsGUI:
    def __init__(self, root: tk.Tk):
        self.results = {}
        self.cleanexit = False
        self.back = False

        self.root = tk.Toplevel(root)
        self.root.title(WINDOW_TITLE)

        # Set geometry
        width = 550
        height = 200 + (25 * (len(InputConfigFlags) + 2))
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        x = (screen_width - width) // 2
        y = ((screen_height - height) // 2) - 50
        self.root.geometry(f"{width}x{height}+{x}+{y}")

        self.output_path = tk.StringVar(
            master=self.root
        )

        self.output_format = tk.StringVar(
            master=self.root,
            value="Excel"
        )

        self._updating = False

        # ─── File Path Selector and Format ────────────────────
        path_frame = tk.Frame(self.root)
        path_frame.pack(
            pady=15,
            padx=10,
            fill="x"
        )

        tk.Label(
            path_frame,
            text="Select Output File:",
            anchor="w"
        ).pack(
            anchor="w"
        )

        path_entry = tk.Entry(
            path_frame,
            textvariable=self.output_path
        )

        path_entry.pack(
            side=tk.LEFT,
            fill="x",
            expand=True,
            padx=(0, 5)
        )

        format_box = tk.OptionMenu(
            path_frame,
            self.output_format,
            *FORMAT_MAP.keys()
        )

        format_box.pack(
            side=tk.LEFT,
            padx=(0, 5)
        )

        browse_btn = tk.Button(
            path_frame,
            text="Browse",
            command=self.browse_file
        )

        browse_btn.pack(
            side=tk.LEFT
        )

        self.output_path.trace_add(
            "write",
            self._path_changed
        )

        self.output_format.trace_add(
            "write",
            self._format_changed
        )

        # ─── Checkboxes for Flags ─────────────────────────────
        checkbox_frame = tk.LabelFrame(
            self.root,
            text="Options",
            padx=10,
            pady=10
        )

        checkbox_frame.pack(
            padx=10,
            pady=10,
            fill="both",
            expand=True
        )

        self.flag_bool_vars = {}

        for f in InputConfigFlags:
            # Skip flags not meant for this window
            if GuiWindow.OutfileFlagsGUI not in f.module_visibility:
                continue

            self.flag_bool_vars[f.flag] = tk.BooleanVar(
                master=self.root,
                value=f.default
            )

            self.add_checkbox_with_tooltip(
                checkbox_frame,
                f"Enable {f.flag}",
                self.flag_bool_vars[f.flag],
                f.description
            )

        # ─── Additional Options ─────────────────────────────
        options_frame = tk.Frame(checkbox_frame)

        options_frame.pack(
            pady=5,
            padx=10,
            fill="x"
        )

        self.additional_option_vars = {}

        for opt in InputAdditionalOptions:
            # Skip options not meant for this window
            if GuiWindow.OutfileFlagsGUI not in opt.module_visibility:
                continue

            self.additional_option_vars[opt.opt] = create_tk_variable(
                value=opt.default,
                master=self.root
            )

            self.add_dropdown_with_tooltip(
                options_frame,
                opt.opt.capitalize(),
                self.additional_option_vars[opt.opt],
                opt.description,
                opt.values
            )

        # ─── Submit Button ─────────────────────────────
        button_frame = tk.Frame(self.root)

        button_frame.pack(
            pady=10
        )

        back_button = tk.Button(
            button_frame,
            text="Go Back",
            command=self.go_back
        )

        back_button.pack(
            side=tk.LEFT,
            padx=(0, 10)
        )

        submit_button = tk.Button(
            button_frame,
            text="Submit",
            command=self.submit
        )

        submit_button.pack(
            side=tk.LEFT
        )

        # Version text
        VersionLabel(self.root).pack(
            side=tk.BOTTOM,
            pady=5
        )


        # Keep the window hidden until load_view() is called.
        self.root.withdraw()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self._on_close
        )

    def _populate_view(
        self,
        outfile="",
        control_flags=None,
        initial_additional_options=None
    ):
        """
        Populate the window with the supplied values.

        This is called every time load_view() is called.
        """

        self.cleanexit = False
        self.back = False
        self.results = {}

        self._updating = False

        if control_flags is None:
            initial_flags = {}
        else:
            initial_flags = control_flags

        if initial_additional_options is None:
            initial_options = {}
        else:
            initial_options = initial_additional_options

        # ─── File Path Selector and Format ────────────────────
        self.output_path.set(
            outfile
        )

        fmt = EXT_TO_FORMAT.get(
            os.path.splitext(outfile)[1].lower()
        )

        if fmt:
            self.output_format.set(fmt)
        else:
            self.output_format.set("Excel")

        # ─── Checkboxes for Flags ─────────────────────────────
        for f in InputConfigFlags:
            if GuiWindow.OutfileFlagsGUI not in f.module_visibility:
                continue

            self.flag_bool_vars[f.flag].set(
                initial_flags.get(
                    f.flag,
                    f.default
                )
            )

        # ─── Additional Options ─────────────────────────────
        for opt in InputAdditionalOptions:
            if GuiWindow.OutfileFlagsGUI not in opt.module_visibility:
                continue

            self.additional_option_vars[opt.opt].set(
                initial_options.get(
                    opt.opt,
                    opt.default
                )
            )

        # Make sure the path/format relationship is updated.
        self._path_changed()

    def load_view(self, outfile="", control_flags=None, initial_additional_options=None):
        self.root.withdraw()
        self.back = False
        self.cleanexit = False
        self._populate_view(outfile, control_flags, initial_additional_options)
        self.root.update_idletasks()
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.root.attributes("-topmost", True)
        self.root.update()
        self.root.attributes("-topmost", False)
        self.root.grab_set()
        self.root.mainloop()
        if self.root.winfo_exists():
            try: self.root.grab_release()
            except tk.TclError: pass

    def hide_view(self):
        if self.root.winfo_exists():
            try: self.root.grab_release()
            except tk.TclError: pass
            self.root.withdraw()
            self.root.quit()

    def _on_close(self):
        self.cleanexit = False
        self.results = {}
        self.hide_view()

    def destroy_view(self):
        if not self.root.winfo_exists():
            return
        try: self.root.grab_release()
        except tk.TclError: pass
        self.output_path = None
        self.output_format = None
        self.flag_bool_vars.clear()
        self.additional_option_vars.clear()
        try: self.root.quit()
        except tk.TclError: pass
        try: self.root.destroy()
        except tk.TclError: pass

    def browse_file(self):
        fmt = FORMAT_MAP[
            self.output_format.get()
        ]

        if platform.system() == "Linux" and shutil.which("zenity"):
            filter_str = ", ".join(
                "*{}".format(f['ext'])
                for f in FORMAT_MAP.values()
            )

            result = subprocess.run(
                [
                    "zenity",
                    "--file-selection",
                    "--save",
                    "--confirm-overwrite",
                    "--filename=output{}".format(fmt['ext']),
                    "--file-filter={} files ({}) | {}".format(
                        parsers.PROG_NAME_ABBR,
                        filter_str,
                        filter_str.replace(',', '')
                    )
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                self.output_path.set(
                    result.stdout.strip()
                )

            return

        filetypes = [
            v["filetype"]
            for v in FORMAT_MAP.values()
        ]

        file_path = filedialog.asksaveasfilename(
            title="Select Output File",
            defaultextension=fmt["ext"],
            filetypes=filetypes,
        )

        if file_path:
            self.output_path.set(
                file_path
            )

    def add_checkbox_with_tooltip(
        self,
        parent,
        text,
        variable,
        tooltip_text
    ):
        frame = tk.Frame(parent)

        frame.pack(
            anchor="w",
            pady=2,
            fill="x"
        )

        cb = tk.Checkbutton(
            frame,
            text=text,
            variable=variable
        )

        cb.pack(
            side=tk.LEFT
        )

        q_label = tk.Label(
            frame,
            text="?",
            fg="blue",
            font=("Arial", 10, "bold"),
            cursor="question_arrow"
        )

        q_label.pack(
            side=tk.LEFT,
            padx=5
        )

        ToolTip(
            q_label,
            tooltip_text
        )

    def add_dropdown_with_tooltip(
        self,
        parent,
        text,
        variable,
        tooltip_text,
        values
    ):
        frame = tk.Frame(parent)

        frame.pack(
            anchor="w",
            pady=2,
            fill="x"
        )

        tk.Label(
            frame,
            text=text,
            anchor="w"
        ).pack(
            side=tk.LEFT
        )

        jobs_menu = tk.OptionMenu(
            frame,
            variable,
            *range(
                values[0],
                values[1] + 1
            )
        )

        jobs_menu.pack(
            side=tk.LEFT,
            padx=5
        )

        q_label = tk.Label(
            frame,
            text="?",
            fg="blue",
            font=("Arial", 10, "bold"),
            cursor="question_arrow"
        )

        q_label.pack(
            side=tk.LEFT,
            padx=5
        )

        ToolTip(
            q_label,
            tooltip_text
        )

    def _path_changed(self, *_):
        if self._updating:
            return

        self._updating = True

        _, ext = os.path.splitext(
            self.output_path.get()
        )

        fmt = EXT_TO_FORMAT.get(
            ext.lower()
        )

        if fmt:
            self.output_format.set(
                fmt
            )

        self._updating = False

    def _format_changed(self, *_):
        if self._updating:
            return

        self._updating = True

        filename = self.output_path.get()

        root, ext = os.path.splitext(
            filename
        )

        new_ext = FORMAT_MAP[
            self.output_format.get()
        ]["ext"]

        if ext.lower() in EXT_TO_FORMAT:
            self.output_path.set(
                root + new_ext
            )
        elif filename:
            self.output_path.set(
                filename + new_ext
            )

        self._updating = False

    def go_back(self):
        self.back = True
        self.submit()

    def submit(self):
        output_path = self.output_path.get().strip()

        ext = os.path.splitext(
            output_path.lower()
        )[1]

        # Skip validation check if going back
        if not self.back:
            if ext not in EXT_TO_FORMAT:
                messagebox.showerror(
                    "Invalid File",
                    f"Supported extensions: "
                    f"{', '.join(EXT_TO_FORMAT.keys())}"
                )
                return

        self.results = {
            InputDictKeys.OUTFILE.value: output_path
        } | {
            f.flag: self.flag_bool_vars[f.flag].get()
            for f in InputConfigFlags
            if GuiWindow.OutfileFlagsGUI in f.module_visibility
        } | {
            opt.opt: self.additional_option_vars[opt.opt].get()
            for opt in InputAdditionalOptions
            if GuiWindow.OutfileFlagsGUI in opt.module_visibility
        }

        self.cleanexit = True

        # Hide instead of destroying the window so that
        # the same GUI instance can be reused.
        self.hide_view()
