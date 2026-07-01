# reporting.py

import os
import logging
from .toolbox import console

_plotlib_enabled = False

try:
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    _plotlib_enabled = True
except (ImportError, ModuleNotFoundError):
    _plotlib_enabled = False

logger = logging.getLogger(__name__)

class Report:
    """
    Reporting class to track finding counts and generate images and reports at the end of parsing.\n
    CLI Mode: Print counts and their percentages. Outputs a pie chart image to logs directory.\n
    GUI Mode: Display pie chart and individual counts in a table in a Tkinter window at the very end. Save image out to log directory.
    """
    
    def __init__(self, scanners):
        # Init the counts [findings, errors]
        self.counts = {scanner: [0, 0] for scanner in scanners}
    
    def _get_total(self):
        return [self.get_total_findings(), self.get_total_errors()]
    
    def get_total_findings(self):
        return sum([v[0] for v in self.counts.values()])
    
    def get_total_errors(self):
        return sum([v[1] for v in self.counts.values()])

    def generate_report(self):
        global _plotlib_enabled
        from parsers import PROJ_NAME, PROJ_VERSION, GUI_MODE, LOGS_DIR
        
        # Print CLI and log string here
        outstr = self._cli_table()

        logger.info('\n' + outstr + '\n')
        
        if not GUI_MODE:
            print(outstr)
        
        # Create pie charts
        if not _plotlib_enabled:
            console(f"Unable to generate plot charts because matplotlib failed to import. Check logs in \"{LOGS_DIR}\" for finding reports.", "Import Error", type='error', orig_name=__name__)
            return
        
        # Create chart figure
        fig = self._build_chart()

        # Always save PNG
        fname = "_".join(part for part in [PROJ_NAME.replace(' ', '_'), PROJ_VERSION.replace(' ', '_'), "Findings.png"] if len(part.strip()) > 0)
        outpath = os.path.join(LOGS_DIR, fname)
        fig.savefig(
            outpath,
            bbox_inches="tight"
        )
        
        logger.info(f"Report chart saved to \"{outpath}\"")

        # Only display GUI if enabled
        if GUI_MODE:
            self._gui_chart(fig)
                    
    def _build_chart(self):
        from parsers import PROJ_NAME, PROJ_VERSION
        findings = [i[0] for i in self.counts.values()]
        labels = list(self.counts.keys())

        fig = Figure(
            figsize=(10, 6),
            dpi=100,
            constrained_layout=True
        )

        ax = fig.add_subplot(111)
        
        ax.set_title(
            " ".join(part for part in [PROJ_NAME, PROJ_VERSION, "Findings"] if part.strip()),
            fontsize=16,
            pad=20
        )

        explode = [0.03] * len(findings)

        def make_autopct(values):
            def autopct(pct):
                value = int(round(pct / 100 * sum(findings)))
                if value == 0:
                    return ""
                return f"{pct:.1f}%\n({value})"
            return autopct
        
        if sum(findings) <= 0:
            from matplotlib.patches import Circle
            ax.clear()
            ax.set_axis_off()

            circle = Circle((0, 0), 1, fill=False)
            ax.add_patch(circle)

            ax.text(
                0,
                0,
                "No Findings",
                ha="center",
                va="center",
            )

            ax.set_xlim(-1.1, 1.1)
            ax.set_ylim(-1.1, 1.1)
            ax.set_aspect("equal")
            return fig
        else:
            wedges, texts, autotexts = ax.pie(
                findings,
                autopct=make_autopct(findings),
                startangle=90,
                explode=explode,
                labeldistance=1.3, # Move labels outward
                pctdistance=0.85, # Move percentages inward
            )

        ax.legend(
            wedges,
            labels,
            loc="center left",
            bbox_to_anchor=(0.82, 0.5)
        )

        # Donut center
        centre_circle = plt.Circle(
            (0, 0),
            0.60,
            fc="white"
        )

        ax.add_artist(centre_circle)

        # Total in center
        ax.text(
            0,
            0.065,
            f"Total",
            ha="center",
            va="center",
            fontsize=14,
            fontweight="bold"
        )
        
        # Second line of text with the actual total
        ax.text(
            0,
            -0.065,
            str(self.get_total_findings()),
            ha="center",
            va="center",
            fontsize=14,
            fontweight="bold"
        )

        ax.axis("equal")
        
        return fig
    
    def _gui_chart(self, fig):
        from parsers import PROG_NAME, VERSION, LOGFILE
        import tkinter as tk

        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

        root = tk.Tk()

        root.title(f"{PROG_NAME} Report")
        root.geometry("900x800")
        root.minsize(700, 600)

        total_findings, total_errors = self._get_total()

        # =========================
        # Table
        # =========================

        table_container = tk.Frame(root)
        table_container.pack(
            pady=10
        )

        table_frame = tk.Frame(table_container)
        table_frame.pack(anchor="center")

        headers = ["Scanner", "Findings", "Percentage", "Errors"]

        for col, text in enumerate(headers):
            lbl = tk.Label(
                table_frame,
                text=text,
                font=("TkDefaultFont", 10, "bold"),
                padx=10,
                pady=5
            )

            lbl.grid(
                row=0,
                column=col,
                sticky="ew"
            )

        for row_index, (scanner, values) in enumerate(self.counts.items(), start=1):
            findings_count = values[0]
            errors_count = values[1]

            percentage = (
                (findings_count / total_findings) * 100
                if total_findings > 0 else 0
            )

            # Scanner
            tk.Label(
                table_frame,
                text=scanner,
                padx=10,
                pady=3,
                anchor="w"
            ).grid(
                row=row_index,
                column=0,
                sticky="ew"
            )

            # Findings
            tk.Label(
                table_frame,
                text=findings_count,
                padx=10,
                pady=3
            ).grid(
                row=row_index,
                column=1,
                sticky="ew"
            )

            # Percentage
            tk.Label(
                table_frame,
                text=f"{percentage:.1f}%",
                padx=10,
                pady=3
            ).grid(
                row=row_index,
                column=2,
                sticky="ew"
            )

            # Errors
            error_kwargs = {}

            if errors_count > 0:
                error_kwargs = {
                    "fg": "red",
                    "font": ("TkDefaultFont", 10, "bold")
                }

            tk.Label(
                table_frame,
                text=errors_count,
                padx=10,
                pady=3,
                **error_kwargs
            ).grid(
                row=row_index,
                column=3,
                sticky="ew"
            )

        # =========================
        # Total Row
        # =========================

        total_row = len(self.counts) + 1

        bold_font = ("TkDefaultFont", 10, "bold")

        tk.Label(
            table_frame,
            text="Total",
            font=bold_font,
            padx=10,
            pady=6
        ).grid(
            row=total_row,
            column=0,
            sticky="ew"
        )

        tk.Label(
            table_frame,
            text=total_findings,
            font=bold_font,
            padx=10,
            pady=6
        ).grid(
            row=total_row,
            column=1,
            sticky="ew"
        )

        tk.Label(
            table_frame,
            text="100.0%",
            font=bold_font,
            padx=10,
            pady=6
        ).grid(
            row=total_row,
            column=2,
            sticky="ew"
        )

        total_error_kwargs = {
            "font": bold_font
        }

        if total_errors > 0:
            total_error_kwargs["fg"] = "red"

        # Errors value
        tk.Label(
            table_frame,
            text=total_errors,
            padx=10,
            pady=6,
            **total_error_kwargs
        ).grid(
            row=total_row,
            column=3,
            sticky="ew"
        )

        # Optional tooltip icon
        if total_errors > 0:

            tooltip = None

            def show_tooltip(event):
                nonlocal tooltip

                tooltip = tk.Toplevel(root)
                tooltip.wm_overrideredirect(True)

                x = event.x_root + 10
                y = event.y_root + 10

                tooltip.wm_geometry(f"+{x}+{y}")

                tk.Label(
                    tooltip,
                    text=f"Please see logfile \"{LOGFILE}\" for more details.",
                    background="#ffffe0",
                    relief="solid",
                    borderwidth=1,
                    padx=6,
                    pady=4
                ).pack()

            def hide_tooltip(event):
                nonlocal tooltip

                if tooltip is not None:
                    tooltip.destroy()
                    tooltip = None

            info_label = tk.Label(
                table_frame,
                text="?",
                fg="blue",
                cursor="question_arrow",
                font=("Arial", 10, "bold")
            )

            info_label.grid(
                row=total_row,
                column=4,
                sticky="w",
                padx=(0, 8)
            )

            info_label.bind("<Enter>", show_tooltip)
            info_label.bind("<Leave>", hide_tooltip)

        # =========================
        # Center Chart In Window
        # =========================

        chart_frame = tk.Frame(root)
        chart_frame.pack(
            fill="both",
            expand=True,
            pady=(0, 10)
        )

        canvas = FigureCanvasTkAgg(
            fig,
            master=chart_frame
        )

        canvas.draw()

        canvas.get_tk_widget().pack(
            anchor="center",
            expand=True
        )
        
        # Version text
        version_label = tk.Label(root, text=f"{PROG_NAME} {VERSION}", font=("Arial", 8), fg="gray")
        version_label.pack(side="bottom", pady=5)

        root.mainloop()
    
    def _cli_table(self):
        _max_key_len = max([len(k) for k in self.counts.keys()])
        _max_val_len = max([len(str(v[0])) for v in self.counts.values()])
        
        if _max_key_len <= 10 or _max_val_len <= 3:
            _pad = 4
        else:
            _pad = 0
        
        outstr = "\nScanner{}\tFindings\tPercentage\tErrors".format(' '*(max(_max_key_len-len("Findings")-1, _pad)))
        outstr += "\n—————————————————————————————————————————————————————————————\n"
        
        total_findings = self.get_total_findings()
        total_errors = self.get_total_errors()
        for k, v in self.counts.items():
            # Findings count
            percentage = f"{(v[0] / total_findings)*100:.1f}%" if total_findings != 0 else "0.0%"
            space = ' '*(max(_max_key_len-len(k), _pad))
            outstr += f"{k}:{space}\t{str(v[0]).rjust(_max_val_len)}\t\t{percentage.rjust(6)}"
            
            # Error count
            outstr += f"\t\t{v[1]}"
            outstr += '\n'
        
        # Calculate total
        space = ' '*(max(_max_key_len-len("Total")+1, _pad))
        outstr += f"\nTotal:{space}\t{str(total_findings).rjust(_max_val_len)}\t\t{'100.0%'.rjust(6)}"
        total_errors = self.get_total_errors()
        outstr += f"\t\t{total_errors}"
        
        outstr += '\n'
        outstr += "—————————————————————————————————————————————————————————————"
        
        return outstr
