"""Explicit preflight consent; no unconfigured task is silently executed or lost."""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk
from .theme import BG, INPUT, TEXT, MUTED, RED, MONO


class PlanReview(tk.Toplevel):
    def __init__(self, parent, plan):
        super().__init__(parent)
        from .gui import frame, label, button, table, readonly_text, put_text
        self.result = None
        self.plan = plan
        self.title('Review investigation plan')
        self.configure(bg=BG)
        self.transient(parent)
        self.minsize(680, 460)
        width = min(1040, max(680, self.winfo_screenwidth() - 90))
        height = min(690, max(460, self.winfo_screenheight() - 100))
        self.geometry(f'{width}x{height}')
        body = frame(self); body.pack(fill='both', expand=True, padx=22, pady=18)
        label(body, 'Review before execution', 19, bold=True).pack(anchor='w')
        text = (f'{len(plan.selected)} selected plugins  /  {len(plan.items)} ready tasks  /  '
                f'{len(plan.deferred)} need attention  /  {len(plan.missing)} unavailable')
        label(body, text, 10, MUTED, anchor='w').pack(fill='x', pady=(8, 8))
        explanation = label(body, 'Run ready tasks skips only the items listed below and records the gap in the case and reports. '
                            'Ready means input validation passed, not that the capture or symbols are guaranteed compatible.',
                            10, MUTED, anchor='w', justify='left', wraplength=920)
        explanation.pack(fill='x', pady=(0, 12))
        explanation.bind('<Configure>', lambda e: explanation.configure(wraplength=max(300, e.width)))
        # Buttons stay visible even with a long list of 100+ plugins.
        actions = frame(body); actions.pack(side='bottom', fill='x', pady=(12, 0))
        button(actions, 'Cancel', self.cancel).pack(side='left')
        self.configure_button = button(actions, 'Configure selected', self.configure_selected)
        self.configure_button.pack(side='left', padx=8)
        if not plan.deferred:
            self.configure_button.configure(state='disabled')
        self.run_button = button(actions, f'Run {len(plan.items)} ready tasks', self.run_ready, True)
        self.run_button.pack(side='right')
        if not plan.items:
            self.run_button.configure(state='disabled')
        notebook = ttk.Notebook(body); notebook.pack(fill='both', expand=True)
        attention = frame(notebook); ready = frame(notebook); notes = frame(notebook)
        notebook.add(attention, text=f'Needs attention ({len(plan.deferred)})')
        notebook.add(ready, text=f'Ready tasks ({len(plan.items)})')
        notebook.add(notes, text='Coverage and handling')
        box, self.issue_tree = table(attention, ('Plugin', 'Status'), [650, 150], height=7)
        box.pack(fill='both', expand=True, pady=(10, 8), padx=8)
        self.issue_detail = readonly_text(attention, height=5)
        self.issue_detail.pack(fill='x', padx=8, pady=(0, 8))
        for i, item in enumerate(plan.deferred):
            self.issue_tree.insert('', 'end', iid=str(i), values=(item['plugin'], item['status']))
        self.issue_tree.bind('<<TreeviewSelect>>', self.show_issue)
        self.issue_tree.bind('<Double-1>', lambda e: self.configure_selected())
        if plan.deferred:
            self.issue_tree.selection_set('0'); self.show_issue()
        else:
            put_text(self.issue_detail, 'No plugin input problems were detected in this plan.')
            notebook.select(ready)
        box, ready_tree = table(ready, ('Plugin / task', 'Arguments'), [440, 450], height=12)
        box.pack(fill='both', expand=True, padx=8, pady=10)
        for p, args in plan.items:
            ready_tree.insert('', 'end', values=(p['name'], ' '.join(args) or '(engine defaults)'))
        details = readonly_text(notes, height=15)
        details.pack(fill='both', expand=True, padx=8, pady=10)
        messages = ['UNAVAILABLE REQUESTED PLUGINS', *(plan.missing or ['None.']), '', 'NOTES',
                    *(plan.notices or ['No additional handling notices.']), '',
                    'Unconfigured plugins stay checked. Configure their options and start again to include them.',
                    'Unavailable and deferred tasks are not counted as successful or as evidence of no findings.']
        put_text(details, '\n'.join(messages))
        self.protocol('WM_DELETE_WINDOW', self.cancel)
        self.bind('<Escape>', lambda e: self.cancel())
        self.update_idletasks()
        self.grab_set()

    def show_issue(self, event=None):
        from .gui import put_text
        selected = self.issue_tree.selection()
        if selected:
            issue = self.plan.deferred[int(selected[0])]
            put_text(self.issue_detail, issue['plugin'] + '\n\n' + issue['reason'])

    def configure_selected(self):
        selected = self.issue_tree.selection()
        if selected:
            self.result = ('configure', self.plan.deferred[int(selected[0])]['plugin'])
            self.destroy()

    def run_ready(self):
        if self.plan.items:
            self.result = ('run', None)
            self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()
