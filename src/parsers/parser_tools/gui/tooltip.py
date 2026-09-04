# tooltip.py

import tkinter as tk

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
        label = tk.Label(tw, text=self._wrap_text(self.text), background="lightyellow",
                         relief="solid", borderwidth=1, padx=5, pady=3,
                         font=("Arial", 9))
        label.pack()

    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None
    
    def _wrap_text(self, text, max_length=100):
        words = text.split()
        lines = []
        current_line = []

        for word in words:
            # Length excluding whitespace
            current_length = sum(len(w) for w in current_line)

            if current_line and current_length + len(word) > max_length:
                lines.append(" ".join(current_line))
                current_line = [word]
            else:
                current_line.append(word)

        if current_line:
            lines.append(" ".join(current_line))

        return "\n".join(lines)