import tkinter as tk
from tkinter import ttk, messagebox

from .. import PROG_NAME, VERSION
from .prule import PRule, Condition, ConditionGroup, Strictness
from .toolbox import Fieldnames

WINDOW_TITLE = "Rule Builder"
WINDOW_LENGTH = 1100
WINDOW_HEIGHT = 750

BG_COLOR1 = "#ffffff" 
BG_COLOR2 = "#e0e0e0"

class ConditionFrame:
    def __init__(self, master, bg=None, remove_callback=None):
        self.frame = tk.Frame(master, relief=tk.RIDGE, borderwidth=1, bg=bg)

        self.remove_callback = remove_callback

        tk.Label(self.frame, text="Field", bg=bg).grid(row=0, column=0, padx=5)
        self.field = ttk.Combobox(
            self.frame,
            values=Fieldnames.HEADERS.value,
            state="readonly"
        )
        self.field.grid(row=0, column=1, padx=5)

        tk.Label(self.frame, text="Match", bg=bg).grid(row=0, column=2, padx=5)
        self.strictness = ttk.Combobox(
            self.frame,
            values=[s.value for s in Strictness],
            state="readonly",
            width=12
        )
        self.strictness.current(0)
        self.strictness.grid(row=0, column=3, padx=5)
        
        self.frame.columnconfigure(5, weight=3)

        tk.Label(self.frame, text="Pattern", bg=bg).grid(row=0, column=4, padx=5, sticky='w')
        self.pattern = tk.Entry(self.frame)
        self.pattern.grid(row=0, column=5, padx=5, sticky="ew")

        self.case = tk.BooleanVar()
        tk.Checkbutton(
            self.frame,
            text="Case Sensitive",
            variable=self.case,
            bg=bg
        ).grid(row=0, column=6)

        tk.Button(
            self.frame,
            text="Delete",
            command=self.remove
        ).grid(row=0, column=7, padx=5)

    def remove(self):
        if self.remove_callback:
            self.remove_callback(self)

    def get_condition(self):
        strictness = Strictness(self.strictness.get())

        return Condition(
            fieldname=self.field.get(),
            pattern=self.pattern.get(),
            strictness=strictness,
            case_sensitive=self.case.get()
        )


class ConditionGroupFrame:

    def __init__(self, master, bg=None, remove_callback=None):

        self.master = master
        self.remove_callback = remove_callback
        self.bg = bg

        self.children = []

        self.frame = tk.Frame(master, relief=tk.GROOVE, borderwidth=2, bg=bg)

        top = tk.Frame(self.frame, bg=bg)
        top.pack(fill="x")

        tk.Label(top, text="Operator", bg=bg).pack(side=tk.LEFT)

        self.operator = ttk.Combobox(
            top,
            values=["AND", "OR", "NOT"],
            width=5,
            state="readonly"
        )
        self.operator.current(0)
        self.operator.pack(side=tk.LEFT, padx=5)

        tk.Button(
            top,
            text="Add Condition",
            command=self.add_condition
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            top,
            text="Add Group",
            command=self.add_group
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            top,
            text="Delete",
            command=self.remove
        ).pack(side=tk.RIGHT)

        self.child_frame = tk.Frame(self.frame, bg=bg)
        self.child_frame.pack(fill="both", expand=True, padx=15, pady=5)

        self.add_condition()

    def remove(self):
        if self.remove_callback:
            self.remove_callback(self)

    def add_condition(self):

        cond = ConditionFrame(
            self.child_frame,
            bg=self.bg,
            remove_callback=self.remove_child
        )

        cond.frame.pack(fill="x", pady=2)

        self.children.append(cond)

    def add_group(self):

        group = ConditionGroupFrame(
            self.child_frame,
            bg=self.bg,
            remove_callback=self.remove_child
        )

        group.frame.pack(fill="x", pady=5)

        self.children.append(group)

    def remove_child(self, child):
        child.frame.destroy()
        self.children.remove(child)

        if len(self.children) == 0:
            self.add_condition()

    def set_bg(self, bg):
        self.bg = bg
        self.frame.configure(bg=bg)
        self.child_frame.configure(bg=bg)

        for child in self.children:
            if isinstance(child, ConditionFrame):
                child.frame.configure(bg=bg)
            else:
                child.set_bg(bg)

    def get_group(self):

        operator = self.operator.get()

        conditions = []

        for child in self.children:

            if isinstance(child, ConditionFrame):
                conditions.append(child.get_condition())

            else:
                conditions.append(child.get_group())

        return ConditionGroup(operator=operator, conditions=conditions)


class ReplacementEditor:

    def __init__(self, parent, replacement, fieldnames, rule_id=None, precedence=None):

        self.result = replacement.copy()
        self.fieldnames = fieldnames
        self.rows = []

        self.root = tk.Toplevel(parent)
        self.root.title(f"Replacement for \"{rule_id}\" ({precedence})")
        self.root.geometry("400x400")
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.frame = tk.Frame(self.root)
        self.frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.rows_frame = tk.Frame(self.frame)
        self.rows_frame.pack(fill="both", expand=True)

        btn_frame = tk.Frame(self.frame)
        btn_frame.pack(pady=5)

        tk.Button(
            btn_frame,
            text="Add Field",
            command=self.add_row
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            btn_frame,
            text="Done",
            command=self.done
        ).pack(side=tk.LEFT, padx=5)
        
        if len(self.result) <= 0:
            self.add_row()
        else:
            for k, v in self.result.items():
                self.add_row(k, v)

        self.refresh_dropdowns()

        self.root.grab_set()
        self.root.wait_window()

    def get_used_fields(self):
        return [row[0].get() for row in self.rows if row[0].get()]

    def refresh_dropdowns(self):
        used = self.get_used_fields()

        for dropdown, _ in self.rows:
            current = dropdown.get()
            available = [f for f in self.fieldnames if f not in used or f == current]
            dropdown['values'] = available

    def add_row(self, field=None, value=""):

        row_frame = tk.Frame(self.rows_frame)
        row_frame.pack(fill="x", pady=2)

        dropdown = ttk.Combobox(
            row_frame,
            state="readonly"
        )

        if field:
            dropdown.set(field)

        dropdown.pack(side=tk.LEFT, padx=5)

        entry = tk.Entry(row_frame)
        entry.insert(0, value)
        entry.pack(side=tk.LEFT, fill="x", expand=True, padx=5)

        def remove():
            row_frame.destroy()
            self.rows.remove((dropdown, entry))
            self.refresh_dropdowns()

        tk.Button(row_frame, text="Delete", command=remove).pack(side=tk.LEFT)

        dropdown.bind("<<ComboboxSelected>>", lambda e: self.refresh_dropdowns())

        self.rows.append((dropdown, entry))
        self.refresh_dropdowns()

    def on_close(self):
        self.done()

    def done(self):

        self.result = {}

        for dropdown, entry in self.rows:
            field = dropdown.get()
            val = entry.get()
            if field:
                self.result[field] = val

        self.root.destroy()

class RootConditionFrame:

    def __init__(self, master, bg=None):

        self.master = master
        self.bg = bg
        self.children = []

        self.frame = tk.Frame(master, bg=bg)

        top = tk.Frame(self.frame, bg=bg)
        top.pack(fill="x")

        tk.Button(
            top,
            text="Add Condition",
            command=self.add_condition
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            top,
            text="Add Group",
            command=self.add_group
        ).pack(side=tk.LEFT, padx=5)

        self.child_frame = tk.Frame(self.frame, bg=bg)
        self.child_frame.pack(fill="both", expand=True, padx=15, pady=5)

        self.add_condition()

    def add_condition(self):

        cond = ConditionFrame(
            self.child_frame,
            bg=self.bg,
            remove_callback=self.remove_child
        )

        cond.frame.pack(fill="x", pady=2)
        self.children.append(cond)

    def add_group(self):

        group = ConditionGroupFrame(
            self.child_frame,
            bg=self.bg,
            remove_callback=self.remove_child
        )

        group.frame.pack(fill="x", pady=5)
        self.children.append(group)

    def remove_child(self, child):
        child.frame.destroy()
        self.children.remove(child)

        if len(self.children) == 0:
            self.add_condition()

    def get_conditions(self):

        conditions = []

        for child in self.children:
            if isinstance(child, ConditionFrame):
                conditions.append(child.get_condition())
            else:
                conditions.append(child.get_group())

        return conditions


class RuleFrame:

    def __init__(self, master, index=0, remove_callback=None, move_up=None, move_down=None, rule_data=None):

        self.master = master
        self.remove_callback = remove_callback
        self.move_up_callback = move_up
        self.move_down_callback = move_down

        self.bg = BG_COLOR1 if index % 2 == 0 else BG_COLOR2

        self.frame = tk.Frame(master, relief=tk.RAISED, borderwidth=2, bg=self.bg)

        header = tk.Frame(self.frame, bg=self.bg)
        header.pack(fill="x")

        tk.Label(header, text="Rule ID", bg=self.bg).pack(side=tk.LEFT)
        self.rule_id = tk.Entry(header, width=20)
        self.rule_id.pack(side=tk.LEFT, padx=5)

        tk.Label(header, text="Precedence", bg=self.bg).pack(side=tk.LEFT)

        self.precedence_var = tk.StringVar(value="1")

        self.precedence = tk.Label(
            header,
            textvariable=self.precedence_var,
            width=3,
            relief=tk.SUNKEN
        )
        self.precedence.pack(side=tk.LEFT, padx=5)

        tk.Button(
            header,
            text="↑",
            command=self.move_up
        ).pack(side=tk.LEFT)

        tk.Button(
            header,
            text="↓",
            command=self.move_down
        ).pack(side=tk.LEFT)
        
        tk.Button(
            header,
            text="Edit Replacement",
            command=self.edit_replacement
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            header,
            text="Delete Rule",
            command=self.remove
        ).pack(side=tk.RIGHT)

        self.group = RootConditionFrame(self.frame, bg=self.bg)
        self.group.frame.pack(fill="both", expand=True, pady=5)
        
        self.replacement = {}

        if rule_data:
            self.load_rule(rule_data)

    def set_bg(self, bg):
        self.bg = bg
        self.frame.configure(bg=bg)
        self.group.set_bg(bg)

    def move_up(self):
        if self.move_up_callback:
            self.move_up_callback(self)

    def move_down(self):
        if self.move_down_callback:
            self.move_down_callback(self)

    def remove(self):
        if self.remove_callback:
            self.remove_callback(self)

    def set_precedence(self, value):
        self.precedence_var.set(str(value))

    def get_precedence(self):
        return int(self.precedence_var.get())

    def edit_replacement(self):
        editor = ReplacementEditor(self.frame, getattr(self, 'replacement', {}), Fieldnames.HEADERS.value, self.rule_id.get(), self.get_precedence())
        self.replacement = editor.result
        
    def load_rule(self, rule):

        self.rule_id.insert(0, rule.rule_id)

        self.replacement = rule.replacement.copy() if rule.replacement else {}

        # Load condition tree
        self.group.frame.destroy()
        self.group = RootConditionFrame(
            self.frame,
            bg=self.bg
        )
        self.group.frame.pack(fill="both", expand=True, pady=5)

        self.load_root(self.group, rule.condition)
    
    def load_group(self, group_frame, group_data):

        group_frame.operator.set(group_data.operator)

        # remove default child
        for child in group_frame.children[:]:
            child.frame.destroy()
            group_frame.children.remove(child)

        for cond in group_data.conditions:

            if isinstance(cond, Condition):

                cf = ConditionFrame(
                    group_frame.child_frame,
                    bg=self.bg,
                    remove_callback=group_frame.remove_child
                )

                cf.field.set(cond.fieldname)
                cf.pattern.insert(0, cond.pattern)
                cf.strictness.set(cond.strictness.value)
                cf.case.set(cond.case_sensitive)

                cf.frame.pack(fill="x", pady=2)
                group_frame.children.append(cf)

            else:

                sub = ConditionGroupFrame(
                    group_frame.child_frame,
                    bg=self.bg,
                    remove_callback=group_frame.remove_child
                )

                sub.frame.pack(fill="x", pady=5)
                group_frame.children.append(sub)

                self.load_group(sub, cond)
    
    def load_root(self, root_frame, group_data):

        for child in root_frame.children[:]:
            child.frame.destroy()
            root_frame.children.remove(child)

        for cond in group_data.conditions:

            if isinstance(cond, Condition):

                cf = ConditionFrame(
                    root_frame.child_frame,
                    bg=self.bg,
                    remove_callback=root_frame.remove_child
                )

                cf.field.set(cond.fieldname)
                cf.pattern.insert(0, cond.pattern)
                cf.strictness.set(cond.strictness.value)
                cf.case.set(cond.case_sensitive)

                cf.frame.pack(fill="x", pady=2)
                root_frame.children.append(cf)

            else:

                sub = ConditionGroupFrame(
                    root_frame.child_frame,
                    bg=self.bg,
                    remove_callback=root_frame.remove_child
                )

                sub.frame.pack(fill="x", pady=5)
                root_frame.children.append(sub)

                self.load_group(sub, cond)

    def get_rule(self):

        return PRule(
            rule_id=self.rule_id.get(),
            precedence=max(1, self.get_precedence()),
            condition=ConditionGroup(
                operator="AND",
                conditions=self.group.get_conditions()
            ),
            replacement=getattr(self, 'replacement', {})
        )


class RuleBuilderGUI:

    def __init__(self, rules=None):

        self.result = None
        self.enable_default_rules = None
        self.rules = []

        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.geometry(f"{WINDOW_LENGTH}x{WINDOW_HEIGHT}")

        container = tk.Frame(self.root)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        canvas = tk.Canvas(container)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)

        self.rule_frame = tk.Frame(canvas)

        window = canvas.create_window((0, 0), window=self.rule_frame, anchor="nw")
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        def on_config(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas(event):
            canvas.itemconfig(window, width=event.width)

        self.rule_frame.bind("<Configure>", on_config)
        canvas.bind("<Configure>", on_canvas)

        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")

        def _bind_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
            canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))

        def _unbind_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        control = tk.Frame(self.root)
        control.pack()
        
        # Enable Default Rules checkbox
        self.cb_enable_default_rules = tk.BooleanVar(value=True)

        # default_frame = tk.Frame(self.root)
        # default_frame.pack(fill='x', padx=10, pady=(5,0))

        tk.Checkbutton(
            control,
            text="Enable Default Rule Profile",
            variable=self.cb_enable_default_rules
        ).pack(side="top", pady=6)

        tk.Button(
            control,
            text="Add Rule",
            command=self.add_rule
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            control,
            text="Submit",
            command=self.submit
        ).pack(side=tk.LEFT, padx=10)

        if rules is not None:
            for rule in rules:
                self.add_rule(rule)
        else: self.add_rule()

        version_label = tk.Label(
            self.root,
            text=f"{PROG_NAME} {VERSION}",
            font=("Arial", 8),
            fg="gray"
        )
        version_label.pack(side="bottom", pady=5)

        self.root.mainloop()

    def refresh_colors(self):
        for i, rule in enumerate(self.rules):
            bg = BG_COLOR1 if i % 2 == 0 else BG_COLOR2
            rule.frame.configure(bg=bg)

    def add_rule(self, rule_data=None):

        rule = RuleFrame(
            self.rule_frame,
            index=len(self.rules),
            remove_callback=self.remove_rule,
            move_up=self.move_up,
            move_down=self.move_down,
            rule_data=rule_data
        )

        rule.frame.pack(fill="x", pady=5)

        self.rules.append(rule)
        self.update_precedence()
        self.refresh_colors()

    def remove_rule(self, rule):
        rule.frame.destroy()
        self.rules.remove(rule)
        self.update_precedence()
        self.reorder()
        self.refresh_colors()

    def validate(self):

        ids = set()

        for rule in self.rules:

            rid = rule.rule_id.get().strip()

            if not rid:
                messagebox.showerror("Error", "Rule ID cannot be empty")
                return False

            if rid in ids:
                messagebox.showerror("Error", f"Duplicate Rule ID: {rid}")
                return False

            ids.add(rid)

            if rule.get_precedence() <= 0:
                messagebox.showerror("Error", "Precedence must be > 0")
                return False

        return True

    def reorder(self):

        for rule in self.rules:
            rule.frame.pack_forget()

        for rule in self.rules:
            rule.frame.pack(fill="x", pady=5)

        self.refresh_colors()

    def update_precedence(self):
        for i, rule in enumerate(self.rules, start=1):
            rule.set_precedence(i)

    def move_up(self, rule):
        index = self.rules.index(rule)
        if index > 0:
            self.rules[index], self.rules[index-1] = self.rules[index-1], self.rules[index]
            self.update_precedence()
            self.reorder()

    def move_down(self, rule):
        index = self.rules.index(rule)
        if index < len(self.rules)-1:
            self.rules[index], self.rules[index+1] = self.rules[index+1], self.rules[index]
            self.update_precedence()
            self.reorder()

    def on_close(self):
        self.result = None
        self.enable_default_rules = None
        self.root.destroy()

    def submit(self):

        if not self.validate():
            return

        self.reorder()
        
        self.result = []

        for rule in self.rules:
            self.result.append(rule.get_rule())

        self.enable_default_rules = self.cb_enable_default_rules.get()
        
        self.root.destroy()
