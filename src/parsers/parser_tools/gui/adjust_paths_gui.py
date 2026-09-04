# adjust_paths_gui.py

import os
import tkinter as tk

from .version_label import VersionLabel
from . import WINDOW_TITLE, WINDOW_HEIGHT, WINDOW_LENGTH, center_window
from ..toolbox import InputDictKeys, get_all_previews, generate_preview


class AdjustPathsGUI:
    def __init__(self, root: tk.Tk):
        self.results = {}
        self.cleanexit = False
        self.back = False

        self.root = tk.Toplevel(root)
        self.root.title(WINDOW_TITLE)

        # Set geometry
        width = min(WINDOW_LENGTH + 200, self.root.winfo_screenwidth())
        height = WINDOW_HEIGHT
        center_window(self.root, width, height)

        self.updated_paths = []

        # Scrollable area
        container = tk.Frame(self.root)
        container.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        self.canvas = tk.Canvas(container)

        self.scrollbar = tk.Scrollbar(
            container,
            orient="vertical",
            command=self.canvas.yview
        )

        self.table_frame = tk.Frame(self.canvas)

        self.table_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.inner_window = self.canvas.create_window(
            (0, 0),
            window=self.table_frame,
            anchor="nw"
        )

        def on_canvas_configure(event):
            self.canvas.itemconfig(
                self.inner_window,
                width=event.width
            )

        self.canvas.bind(
            "<Configure>",
            on_canvas_configure
        )

        self.canvas.configure(
            yscrollcommand=self.scrollbar.set
        )

        self.canvas.pack(
            side=tk.LEFT,
            fill="both",
            expand=True
        )

        self.scrollbar.pack(
            side=tk.RIGHT,
            fill="y"
        )

        # Track whether the mouse-wheel bindings are active.
        self._mousewheel_bound = False

        self.path_entries = []
        self._path_vars = []

        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(pady=10)

        self.back_button = tk.Button(
            self.button_frame,
            text="Go Back",
            command=self.go_back
        )

        self.back_button.pack(
            side=tk.LEFT,
            padx=(0, 10)
        )

        self.submit_button = tk.Button(
            self.button_frame,
            text="Save Adjusted Paths",
            command=self.collect_paths
        )

        self.submit_button.pack(
            side=tk.LEFT
        )

        # Version text
        VersionLabel(self.root).pack(
            side=tk.BOTTOM,
            pady=5
        )

        # Keep window hidden until load_view() is called.
        self.root.withdraw()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self._on_close
        )

    # ------------------------------------------------------------------
    # Mouse-wheel handling
    # ------------------------------------------------------------------

    def _on_mousewheel(self, event):
        """
        Handle mouse-wheel scrolling on Windows/macOS.

        bind_all() is used because the widget under the mouse may be
        an Entry or another child of the canvas rather than the canvas
        itself.
        """

        if not self.root.winfo_exists():
            return

        if event.delta:
            # Windows normally reports +/-120 per wheel notch.
            # Some platforms can report smaller values, so make sure
            # a non-zero delta always results in at least one unit.
            units = int(-event.delta / 120)

            if units == 0:
                units = -1 if event.delta > 0 else 1

            self.canvas.yview_scroll(
                units,
                "units"
            )

    def _on_linux_scroll_up(self, event):
        """Handle mouse-wheel up on Linux/X11."""

        if self.root.winfo_exists():
            self.canvas.yview_scroll(
                -1,
                "units"
            )

    def _on_linux_scroll_down(self, event):
        """Handle mouse-wheel down on Linux/X11."""

        if self.root.winfo_exists():
            self.canvas.yview_scroll(
                1,
                "units"
            )

    def _bind_mousewheel(self):
        """
        Enable mouse-wheel scrolling while this GUI is active.

        bind_all() is intentional. Without it, the wheel event can be
        consumed by an Entry widget contained inside the scrolling
        frame instead of reaching the Canvas.
        """

        if self._mousewheel_bound:
            return

        # Windows / macOS
        self.root.bind_all(
            "<MouseWheel>",
            self._on_mousewheel
        )

        # Linux/X11
        self.root.bind_all(
            "<Button-4>",
            self._on_linux_scroll_up
        )

        self.root.bind_all(
            "<Button-5>",
            self._on_linux_scroll_down
        )

        self._mousewheel_bound = True

    def _unbind_mousewheel(self):
        """Disable mouse-wheel scrolling."""

        if not self._mousewheel_bound:
            return

        self.root.unbind_all("<MouseWheel>")
        self.root.unbind_all("<Button-4>")
        self.root.unbind_all("<Button-5>")

        self._mousewheel_bound = False

    # ------------------------------------------------------------------
    # Populate view
    # ------------------------------------------------------------------

    def _populate_view(self, current_inputs):
        """
        Populate the window from current_inputs.

        This is called every time load_view() is called so that
        the GUI always reflects the current input data.
        """

        self.cleanexit = False
        self.back = False
        self.results = {}

        self.previous_results = current_inputs
        self.previews = get_all_previews(current_inputs)

        # Remove all rows from the previous invocation.
        for child in self.table_frame.winfo_children():
            child.destroy()

        self.path_entries.clear()

        # Header row
        tk.Label(
            self.table_frame,
            text="Scanner",
            font=("Arial", 10, "bold"),
            anchor="w"
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=5
        )

        tk.Label(
            self.table_frame,
            text="Substring to Remove",
            font=("Arial", 10, "bold"),
            anchor="w"
        ).grid(
            row=0,
            column=1,
            sticky="ew",
            padx=5
        )

        tk.Label(
            self.table_frame,
            text="Substring to Prepend",
            font=("Arial", 10, "bold"),
            anchor="w"
        ).grid(
            row=0,
            column=2,
            sticky="ew",
            padx=5
        )

        tk.Label(
            self.table_frame,
            text="Preview",
            font=("Arial", 10, "bold"),
            anchor="w"
        ).grid(
            row=0,
            column=3,
            sticky="ew",
            padx=5
        )

        self.table_frame.grid_columnconfigure(
            1,
            weight=1
        )

        self.table_frame.grid_columnconfigure(
            2,
            weight=1
        )

        self.table_frame.grid_columnconfigure(
            3,
            weight=1
        )

        # Live update function
        def update_preview(var1, var2, p, box):
            r = generate_preview(
                self.previews[p],
                var1.get(),
                var2.get()
            )

            box.config(state="normal")
            box.delete(0, tk.END)
            box.insert(0, r)
            box.config(state="readonly")

        # Add path editing rows
        for idx, item in enumerate(
            self.previous_results,
            start=1
        ):
            path = item.get(
                InputDictKeys.PATH.value,
                ""
            )

            scanner = item.get(
                InputDictKeys.SCANNER.value,
                ""
            )

            remove = item.get(
                InputDictKeys.REMOVE.value,
                ""
            )

            prepend = item.get(
                InputDictKeys.PREPEND.value,
                ""
            )

            remove_var = tk.StringVar(
                master=self.root
            )

            add_var = tk.StringVar(
                master=self.root
            )

            remove_entry = tk.Entry(
                self.table_frame,
                textvariable=remove_var
            )

            remove_entry.delete(
                0,
                tk.END
            )

            remove_entry.insert(
                0,
                remove
            )

            add_entry = tk.Entry(
                self.table_frame,
                textvariable=add_var
            )

            add_entry.delete(
                0,
                tk.END
            )

            add_entry.insert(
                0,
                prepend
            )

            preview_box = tk.Entry(
                self.table_frame,
                state="normal",
                readonlybackground="#f0f0f0"
            )

            preview_box.insert(
                0,
                generate_preview(
                    self.previews[path],
                    remove,
                    prepend
                )
            )

            preview_box.config(
                state="readonly"
            )

            # Place them in grid
            tk.Label(
                self.table_frame,
                text=f"{scanner} - {os.path.basename(path)}",
                anchor="w"
            ).grid(
                row=idx,
                column=0,
                sticky="w",
                padx=5,
                pady=5
            )

            remove_entry.grid(
                row=idx,
                column=1,
                sticky="ew",
                padx=5,
                pady=5
            )

            add_entry.grid(
                row=idx,
                column=2,
                sticky="ew",
                padx=5,
                pady=5
            )

            preview_box.grid(
                row=idx,
                column=3,
                sticky="ew",
                padx=5,
                pady=5
            )

            self.table_frame.grid_columnconfigure(
                1,
                weight=1
            )

            self.table_frame.grid_columnconfigure(
                2,
                weight=1
            )

            self.table_frame.grid_columnconfigure(
                3,
                weight=1
            )

            remove_var.trace_add(
                "write",
                lambda *args,
                       v1=remove_var,
                       v2=add_var,
                       p=path,
                       b=preview_box:
                    update_preview(
                        v1,
                        v2,
                        p,
                        b
                    )
            )

            add_var.trace_add(
                "write",
                lambda *args,
                       v1=remove_var,
                       v2=add_var,
                       p=path,
                       b=preview_box:
                    update_preview(
                        v1,
                        v2,
                        p,
                        b
                    )
            )

            self.path_entries.append(
                (
                    scanner,
                    path,
                    remove_var,
                    add_var,
                    preview_box
                )
            )

    # ------------------------------------------------------------------
    # View lifecycle
    # ------------------------------------------------------------------

    def load_view(self, current_inputs):
        self.root.withdraw()

        self.back = False
        self.cleanexit = False
        self._path_vars.clear()

        self._populate_view(current_inputs)

        self.root.update_idletasks()
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

        self.root.attributes("-topmost", True)
        self.root.update()
        self.root.attributes("-topmost", False)

        self.root.grab_set()

        # Enable scrolling while this window is active.
        self._bind_mousewheel()

        self.root.mainloop()

        # Remove scrolling bindings after this view exits.
        self._unbind_mousewheel()

        if self.root.winfo_exists():
            try:
                self.root.grab_release()
            except tk.TclError:
                pass

    def hide_view(self):
        if self.root.winfo_exists():
            self._unbind_mousewheel()

            try:
                self.root.grab_release()
            except tk.TclError:
                pass

            self.root.withdraw()
            self.root.quit()

    def _on_close(self):
        self.cleanexit = False
        self.results = {}
        self.hide_view()

    def destroy_view(self):
        if not self.root.winfo_exists():
            return

        self._unbind_mousewheel()

        try:
            self.root.grab_release()
        except tk.TclError:
            pass

        self._path_vars.clear()

        try:
            self.root.quit()
        except tk.TclError:
            pass

        try:
            self.root.destroy()
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def go_back(self):
        self.back = True
        self.cleanexit = True
        self.hide_view()

    # ------------------------------------------------------------------
    # Collect paths
    # ------------------------------------------------------------------

    def collect_paths(self):
        self.results = []

        for (
            scanner,
            original_path,
            remove_var,
            add_var,
            _
        ) in self.path_entries:
            remove_val = remove_var.get().strip()
            add_val = add_var.get().strip()

            self.results.append({
                InputDictKeys.SCANNER.value: scanner,
                InputDictKeys.PATH.value: original_path,
                InputDictKeys.REMOVE.value: remove_val,
                InputDictKeys.PREPEND.value: add_val
            })

        self.cleanexit = True
        self.hide_view()
