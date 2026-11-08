"""Minimalist Tk/ttk desktop UI. Only the main thread touches Tk widgets."""
from __future__ import annotations
import getpass
import json
import os
import queue
import shutil
import subprocess
import threading
import tkinter as tk
from dataclasses import asdict, replace
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from . import __version__
from .case import Case, verify_audit
from .engine import Settings, discover_plugins, plugin_arguments, run_plugin, triage_plugins
from .exporting import export_report, export_results
from .results import PAGE_SIZE, hunt_case, query_rows
from .diagnostics import collect_log, diagnose, format_diagnosis
from .reports import export_bundle, recover_last_exports
from .summary import build_summary, get_observables
from .paths import user_path, workspace_root, inspect_image, find_dumps, common_locations
from .dialogs import ImportDialog, ExportDialog
from .util import Cancelled, atomic_json, data_root, human_size, tail_text

from .workspace import InvestigationMixin
from .guided import GuidedMixin

from .theme import (BG, SIDE, CARD, INPUT, BORDER, TEXT, MUTED, ACCENT,
                    DARK_ACCENT, GOOD, WARN, RED, FONT, MONO,
                    CutPanel, MemoryGlyph, VerticalPage, set_windows_dark_titlebar)


def frame(parent, color=BG, **kwargs):
    return tk.Frame(parent, bg=color, **kwargs)


def label(parent, text="", size=10, color=TEXT, bold=False, bg=BG, **kwargs):
    selected_font = kwargs.pop("font", (FONT, size, "bold" if bold else "normal"))
    return tk.Label(parent, text=text, bg=bg, fg=color, font=selected_font, **kwargs)


def button(parent, text, command, primary=False, **kwargs):
    return ttk.Button(parent, text=text, command=command,
                      style="Accent.TButton" if primary else "TButton", **kwargs)


def readonly_text(parent, height=8):
    box = tk.Text(parent, bg=INPUT, fg=TEXT, insertbackground=TEXT, wrap="word",
                  font=(MONO, 10), relief="flat", borderwidth=0,
                  padx=14, pady=12, height=height, highlightthickness=1,
                  highlightbackground=BORDER, selectbackground=DARK_ACCENT)
    scroll=ttk.Scrollbar(box,orient="vertical",command=box.yview)
    scroll.place(relx=1,rely=0,relheight=1,anchor="ne")
    box.configure(yscrollcommand=scroll.set,state="disabled")
    return box


def put_text(widget, text):
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", text)
    widget.configure(state="disabled")


def table(parent, columns, widths=None, height=10):
    holder = frame(parent)
    tree = ttk.Treeview(holder, columns=columns, show="headings", height=height,
                        selectmode="browse")
    for i, name in enumerate(columns):
        tree.heading(name, text=name)
        tree.column(name, width=(widths[i] if widths else 150), minwidth=60, stretch=True)
    vertical = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(holder, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    holder.rowconfigure(0, weight=1)
    holder.columnconfigure(0, weight=1)
    tree.tag_configure("alternate", background="#1e1e21")
    return holder, tree


from .evidence_ui import EvidenceMixin

class App(EvidenceMixin, GuidedMixin, InvestigationMixin, tk.Tk):
    def __init__(self, auto_discover=True):
        super().__init__()
        self.title("Test Subject 007")
        self.geometry("1440x900")
        self.minsize(1160, 760)
        self.configure(bg=BG)
        self.case: Case | None = None
        self.catalog = {"version": "not loaded", "plugins": [], "unavailable": []}
        self.catalog_error = ""
        self.events = queue.Queue()
        self.busy = False
        self.refresh_guided()
        self.cancel_event = threading.Event()
        self.closing = False
        self.pages = {}
        self.queue_items = []
        self.current_plugin = None
        self.option_vars = {}
        self.run_items = []
        self.selected_run = ""
        self.page_number = 0
        self.current_rows = {}
        self.hunt_rows = {}
        self.init_investigation_state()
        self.settings = self._load_settings()
        self.export_dir_var = tk.StringVar(value=self.settings.export_dir or str(workspace_root() / "Reports"))
        self.last_export_var = tk.StringVar(value="No reports generated in this session.")
        self.last_export_folder = None
        self._styles()
        self._layout()
        self._app_icon = tk.PhotoImage(width=32, height=32)
        self._app_icon.put(SIDE, to=(0, 0, 32, 32))
        for area in ((4, 4, 15, 6), (4, 4, 6, 16), (17, 26, 28, 28), (26, 16, 28, 28)):
            self._app_icon.put(TEXT, to=area)
        self._app_icon.put(RED, to=(25, 4, 28, 7))
        self.iconphoto(True, self._app_icon)
        self.protocol("WM_DELETE_WINDOW", self.request_close)
        self.bind("<Control-o>", lambda _: self.open_case())
        self.bind("<Control-n>", lambda _: self.import_memory())
        for event in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(event, self._scroll_page, add="+")
        self.show("Overview")
        self.after(100, self._poll)
        self.after(150, lambda: set_windows_dark_titlebar(self))
        for number, page in enumerate(self.pages, 1):
            self.bind(f"<Control-Key-{number}>", lambda _, n=page: self.show(n))
        if auto_discover:
            self.after(200, self.refresh_catalog)

    def _scroll_page(self, event):
        page = self.pages.get(getattr(self, "active_page", ""))
        if getattr(self,"active_page","") == "Analyze" and hasattr(self,"goal_scroll"):
            page = self.goal_scroll
        if not isinstance(page, VerticalPage):
            return
        widget = event.widget
        while widget is not None:
            if widget is page:
                page.scroll_event(event)
                return
            widget = getattr(widget, "master", None)

    def _styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=(FONT, 10), bordercolor=BORDER,
                        lightcolor=BORDER, darkcolor=BORDER)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("TButton", background=CARD, foreground=TEXT, borderwidth=1,
                        relief="flat", padding=(13, 9), focuscolor=BORDER)
        style.map("TButton", background=[("active", BORDER), ("disabled", SIDE)],
                  foreground=[("disabled", "#717179")])
        style.configure("Accent.TButton", background=ACCENT, foreground=BG, font=(FONT, 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#ffffff"), ("disabled", BORDER)],
                  foreground=[("disabled", MUTED)])
        style.configure("TEntry", fieldbackground=INPUT, foreground=TEXT, bordercolor=BORDER,
                        insertcolor=TEXT, padding=8)
        style.map("TEntry", fieldbackground=[("readonly", INPUT)],
                  foreground=[("readonly", MUTED)])
        style.configure("TCombobox", fieldbackground=INPUT, background=CARD, foreground=TEXT,
                        arrowcolor=MUTED, padding=7)
        style.map("TCombobox", fieldbackground=[("readonly", INPUT)],
                  selectbackground=[("readonly", INPUT)], selectforeground=[("readonly", TEXT)])
        self.option_add("*TCombobox*Listbox.background", INPUT)
        self.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", DARK_ACCENT)
        style.configure("TCheckbutton", background=BG, foreground=TEXT, padding=4)
        style.map("TCheckbutton", background=[("active", BG)])
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                        rowheight=29, borderwidth=0, font=(FONT, 9))
        style.configure("Treeview.Heading", background=INPUT, foreground=MUTED,
                        relief="flat", font=(MONO, 9), padding=9)
        style.map("Treeview", background=[("selected", DARK_ACCENT)], foreground=[("selected", TEXT)])
        style.map("Treeview.Heading", background=[("active", BORDER)])
        for orientation in ("Horizontal", "Vertical"):
            key = orientation + ".TScrollbar"
            style.configure(key, background=BORDER, troughcolor=BG, bordercolor=BG,
                            lightcolor=BORDER, darkcolor=BORDER, arrowcolor=MUTED,
                            gripcount=0, borderwidth=0, arrowsize=11)
            style.map(key, background=[("active", "#56565e"), ("!active", BORDER)],
                      lightcolor=[("active", "#56565e"), ("!active", BORDER)],
                      darkcolor=[("active", "#56565e"), ("!active", BORDER)])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=SIDE, foreground=MUTED, padding=(16, 10))
        style.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", TEXT)])
        style.configure("Horizontal.TProgressbar", background=MUTED, troughcolor=SIDE,
                        lightcolor=MUTED, darkcolor=MUTED, bordercolor=BORDER, borderwidth=0)
        style.map("TButton", bordercolor=[("focus", MUTED), ("!focus", BORDER)])

    def _load_settings(self):
        path = data_root() / "settings.json"
        try:
            values = json.loads(path.read_text(encoding="utf-8"))
            return Settings(**{k: v for k, v in values.items() if k in Settings.__dataclass_fields__})
        except (OSError, ValueError, TypeError):
            return Settings(symbols=str(data_root() / "symbols"))

    def _layout(self):
        top = frame(self, SIDE, height=64)
        top.pack(fill="x")
        top.pack_propagate(False)
        brand = frame(top, SIDE)
        brand.pack(side="left", padx=26, pady=14)
        mark = tk.Canvas(brand, width=31, height=32, bg=SIDE, highlightthickness=0)
        mark.pack(side="left", padx=(0, 13))
        mark.create_line(1, 11, 1, 1, 14, 1, fill=TEXT)
        mark.create_line(18, 30, 30, 30, 30, 19, fill=TEXT)
        for x in (9, 15, 21):
            mark.create_line(x, 10, x-4, 22, fill=MUTED)
        mark.create_rectangle(27, 2, 30, 5, fill=RED, outline=RED)
        label(brand, "TEST SUBJECT", 14, bold=True, bg=SIDE).pack(side="left")
        label(brand, "007", 21, color=TEXT, bg=SIDE, font=(MONO, 21)).pack(side="left", padx=(10, 0))
        self.engine_badge = tk.StringVar(value="VOLATILITY 3 / CHECKING")
        label(top, textvariable=self.engine_badge, size=9, color=MUTED, bg=SIDE,
              font=(MONO, 9)).pack(side="right", padx=26)
        label(top, "MEMORY FORENSICS", 8, MUTED, bg=SIDE).pack(side="right", padx=24)
        frame(self, BORDER, height=1).pack(fill="x")
        workspace = frame(self)
        workspace.pack(fill="both", expand=True)
        side = frame(workspace, SIDE, width=170)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        label(side, "WORKSPACE", 8, MUTED, bg=SIDE, font=(MONO, 8)).pack(anchor="w", padx=24, pady=(30, 17))
        self.nav_buttons, self.nav_markers = {}, {}
        for index, name in enumerate(("Overview", "Analyze", "Execution", "Findings", "Evidence lab", "Results", "Case notes", "Settings"), 1):
            row = frame(side, SIDE)
            row.pack(fill="x", padx=(12, 10), pady=4)
            marker = frame(row, SIDE, width=2)
            marker.pack(side="left", fill="y", pady=11)
            nav = tk.Button(row, text={"Overview":"01  Case", "Analyze":"02  Investigate", "Execution":"03  Live run", "Findings":"04  Findings", "Evidence lab":"05  Evidence lab", "Results":"Evidence tables", "Case notes":"Analyst notes", "Settings":"Settings"}[name], command=lambda n=name: self.show(n),
                            bg=SIDE, fg=MUTED, activebackground=CARD, activeforeground=TEXT,
                            relief="flat", borderwidth=0, highlightthickness=0, anchor="w", font=(FONT, 10),
                            padx=12, pady=13, cursor="hand2", takefocus=True)
            nav.pack(side="left", fill="x", expand=True)
            self.nav_buttons[name], self.nav_markers[name] = nav, marker
        bottom = frame(side, SIDE)
        bottom.pack(side="bottom", fill="x", padx=24, pady=24)
        frame(bottom, BORDER, height=1).pack(fill="x", pady=(0, 18))
        label(bottom, "LOCAL WORKSPACE", 8, TEXT, bg=SIDE, font=(MONO, 8)).pack(anchor="w")
        label(bottom, "Evidence stays\non this workstation.", 9, MUTED, bg=SIDE,
              justify="left").pack(anchor="w", pady=(9, 18))
        frame(workspace, BORDER, width=1).pack(side="left", fill="y")
        main = frame(workspace)
        main.pack(side="left", fill="both", expand=True)
        header = frame(main)
        header.pack(fill="x", padx=24, pady=(18, 14))
        left = frame(header)
        left.pack(side="left", fill="x", expand=True)
        self.heading = label(left, "Case workspace", 22, bold=True)
        self.heading.pack(anchor="w")
        self.subheading = label(left, "Evidence first. Analysis in context.", 10, MUTED)
        self.subheading.pack(anchor="w", pady=(8, 0))
        button(header, "Add memory", self.import_memory, True).pack(side="right", padx=(10, 0))
        button(header, "Open case", self.open_case).pack(side="right")
        self.container = frame(main)
        self.container.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        self.container.rowconfigure(0, weight=1)
        self.container.columnconfigure(0, weight=1)
        for name in self.nav_buttons:
            page = VerticalPage(self.container) if name in ("Overview", "Settings") else frame(self.container)
            page.grid(row=0, column=0, sticky="nsew")
            self.pages[name] = page
        self._overview()
        self._analysis()
        self._execution_page()
        self._findings_page()
        self._evidence_page()
        self._results()
        self._hunt()
        self._observables()
        self._notes()
        self._settings_page()
        footer = frame(main, SIDE)
        footer.pack(fill="x", side="bottom", before=self.container)
        self.status_var = tk.StringVar(value="Ready. Import a memory image or open a case.")
        self.footer_status = label(footer, textvariable=self.status_var, color=MUTED, size=9, bg=SIDE,
                                  anchor="w", justify="left", wraplength=680)
        self.footer_status.pack(side="left", fill="x", expand=True, padx=20, pady=12)
        self.footer_status.bind("<Configure>", lambda e: self.footer_status.configure(wraplength=max(260, e.width)))
        self.progress = ttk.Progressbar(footer, length=100, mode="indeterminate")
        self.progress.pack(side="left", padx=10)
        self.cancel_button = button(footer, "Cancel task", self.cancel_task)
        self.cancel_button.configure(state="disabled")
        self.cancel_button.pack(side="right", padx=14, pady=6)
        self._export_dock(main)


    def _export_dock(self, main):
        dock=frame(main,CARD)
        dock.pack(side="bottom",fill="x",before=self.container)
        row=frame(dock,CARD); row.pack(fill="x",padx=20,pady=(10,5))
        label(row,"SAVE REPORTS TO",8,MUTED,bg=CARD,font=(MONO,8)).pack(side="left",padx=(0,12))
        ttk.Entry(row,textvariable=self.export_dir_var).pack(side="left",fill="x",expand=True)
        button(row,"Browse",self.browse_exports).pack(side="left",padx=6)
        button(row,"Use folder",self.save_export_folder).pack(side="left")
        row=frame(dock,CARD); row.pack(fill="x",padx=20,pady=(0,10))
        self.export_last_row=row
        label(row,"LAST SAVED PATH",8,MUTED,bg=CARD,font=(MONO,8)).pack(side="left",padx=(0,10))
        ttk.Entry(row,textvariable=self.last_export_var,state="readonly").pack(side="left",fill="x",expand=True)
        button(row,"Copy path",lambda: self.copy_value(self.last_export_var.get())).pack(side="left",padx=6)
        button(row,"Open folder",self.open_exports).pack(side="left")

    def copy_value(self, value):
        self.clipboard_clear(); self.clipboard_append(str(value))
        self.status_var.set("Copied to clipboard.")

    def browse_exports(self):
        path=filedialog.askdirectory(parent=self,title="Where should reports be saved?",initialdir=str(Path.home()),mustexist=False)
        if path:
            self.export_dir_var.set(path)
            self.save_export_folder()

    def save_export_folder(self):
        if not self.idle_required():
            return
        try:
            destination=user_path(self.export_dir_var.get())
            if self.case:
                from .exporting import safe_destination
                safe_destination(self.case,destination/"destination-check.txt")
                self.case.metadata["export_directory"]=str(destination)
                self.case.save()
                self.case.audit("report_folder_selected",{"directory":str(destination)})
            else:
                destination.mkdir(parents=True,exist_ok=True)
            self.export_dir_var.set(str(destination))
            self.settings=replace(self.settings,export_dir=str(destination))
            atomic_json(data_root()/"settings.json",asdict(self.settings))
            self.status_var.set("Report folder saved. All three report formats use this destination.")
        except Exception as exc:
            messagebox.showerror("Report folder",str(exc),parent=self)

    def open_exports(self):
        if self.last_export_folder and Path(self.last_export_folder).is_dir():
            self.open_directory(Path(self.last_export_folder))
        else:
            try:
                self.open_directory(user_path(self.export_dir_var.get()))
            except Exception as exc:
                messagebox.showerror("Report folder",str(exc),parent=self)

    def _export_completed(self, bundle):
        self.last_export_folder=Path(bundle["folder"])
        self.last_export_var.set(bundle["folder"])
        self.refresh_observables()
        self.status_var.set("Reports saved. Copy the folder below, or open a report in the confirmation window.")
        ExportDialog(self,bundle["paths"])

    def copy_diagnostics(self):
        if self.case and self.selected_run:
            folder=self.case.root/"runs"/self.selected_run
            self.copy_value(self.diagnosis_text.get("1.0","end")+"\n\n"+collect_log(folder))

    def _observables(self):
        page=self.observables_page
        row=frame(page); row.pack(fill="x",pady=8)
        label(row,"AUTOMATIC OBSERVABLES / NOT VERIFIED IOCs",9,MUTED,font=(MONO,9)).pack(side="left")
        button(row,"Refresh",self.rebuild_observables).pack(side="right")
        self.observable_notice=label(page,"No analysis has been summarized yet.",9,MUTED,justify="left",wraplength=900)
        self.observable_notice.pack(anchor="w",pady=(0,8))
        row=frame(page); row.pack(fill="x",pady=(0,8))
        self.observable_filter=tk.StringVar()
        entry=ttk.Entry(row,textvariable=self.observable_filter); entry.pack(side="left",fill="x",expand=True)
        entry.bind("<Return>",lambda _: self.refresh_observables())
        button(row,"Filter observables",self.refresh_observables).pack(side="left",padx=(8,0))
        box,self.observable_tree=table(page,("Type","Value","Records","First source"),[150,400,70,320],height=6)
        box.pack(fill="both",expand=True)
        self.observable_records={}
        self.observable_tree.bind("<Double-1>",self.view_observable)

    def refresh_observables(self):
        if not self.case:
            return
        rows,total=get_observables(self.case,self.observable_filter.get())
        self.observable_tree.delete(*self.observable_tree.get_children())
        self.observable_records={}
        for i,item in enumerate(rows):
            self.observable_records[str(i)]=item
            self.observable_tree.insert("","end",iid=str(i),values=(item['kind'],item['value'],item['occurrences'],item['plugin']+" / row "+str(item['row_id'])))
        self.observable_notice.configure(text=f"{total:,} matching distinct values; showing {len(rows)}. Extracted from latest indexed plugin output, not raw RAM. Full values are in observables.csv.")

    def rebuild_observables(self):
        if not self.case_required():
            return
        case=self.case
        self.task(lambda cancel,emit: build_summary(case,cancel,emit),lambda _: self.refresh_observables(),"Extracting local observables...")

    def view_observable(self, event=None):
        selected=self.observable_tree.selection()
        if selected:
            self.show_record("Unvalidated observable / source reference",self.observable_records[selected[0]])

    def _overview(self):
        page = self.pages["Overview"].body
        self.metrics = {}
        cards = frame(page)
        cards.pack(fill="x")
        for index, (key, title, value) in enumerate((("os", "CAPTURE OS", "No case"),
                ("size", "IMAGE SIZE", "--"), ("hash", "SHA-256", "Not recorded"),
                ("runs", "ANALYSIS RUNS", "0"))):
            card = frame(cards, CARD, highlightbackground=BORDER, highlightthickness=1)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 12, 0))
            cards.columnconfigure(index, weight=1, uniform="metric")
            label(card, title, 8, MUTED, bg=CARD, font=(MONO, 8)).pack(anchor="w", padx=17, pady=(15, 9))
            self.metrics[key] = label(card, value, 16, bold=True, bg=CARD)
            self.metrics[key].pack(anchor="w", padx=17, pady=(0, 16))
        self.hero_panel = CutPanel(page, accent=True)
        self.hero_panel.pack(fill="x", pady=(18, 18))
        hero = self.hero_panel.body
        intro = frame(hero, CARD)
        intro.pack(fill="x", padx=10, pady=(8, 13))
        glyph = MemoryGlyph(intro)
        glyph.pack(side="right", padx=(20, 5))
        words = frame(intro, CARD)
        words.pack(side="left", fill="x", expand=True)
        label(words, "EVIDENCE / ACTIVE CASE", 8, MUTED, bg=CARD, font=(MONO, 8)).pack(anchor="w")
        self.hero_title = label(words, "Begin with a memory image.", 20, bold=True, bg=CARD,
                                justify="left", wraplength=760)
        self.hero_title.pack(anchor="w", pady=(12, 7))
        self.hero_detail = label(words, "Import an acquired capture, record its hash, and investigate.\n"
                                "Your evidence is referenced locally, never uploaded by this interface.",
                                10, MUTED, bg=CARD, justify="left", wraplength=760)
        self.hero_detail.pack(anchor="w")
        words.bind("<Configure>", lambda e: (self.hero_title.configure(wraplength=max(300,e.width)),
                                              self.hero_detail.configure(wraplength=max(300,e.width))))
        self.hash_var = tk.StringVar(value="SHA-256 / calculated when you import an image")
        ttk.Entry(hero, textvariable=self.hash_var, state="readonly", font=(MONO, 9)).pack(fill="x", padx=10, pady=(0, 15))
        actions = frame(hero, CARD)
        actions.pack(fill="x", padx=10, pady=(0, 8))
        self.case_buttons = []
        for title, action, primary in (("Choose investigation", self.run_triage, True),
                                       ("Verify SHA-256", self.verify_image, False),
                                       ("Relink image", self.relink_image, False)):
            item = button(actions, title, action, primary)
            item.pack(side="left", padx=(0, 8))
            item.configure(state="disabled")
            self.case_buttons.append(item)
        folder = button(actions, "Case folder", self.open_case_folder)
        folder.pack(side="right")
        folder.configure(state="disabled")
        self.case_buttons.append(folder)
        row = frame(page)
        row.pack(fill="x", pady=(0, 12))
        label(row, "ANALYSIS HISTORY", 9, TEXT, font=(MONO, 9)).pack(side="left")
        button(row, "Export PDF / HTML / CSV", self.report).pack(side="right")
        box, self.history = table(page, ("Plugin", "Status", "Rows", "Started (UTC)"),
                                  [380, 170, 65, 190], height=6)
        box.pack(fill="both", expand=True)
        self.history.bind("<Double-1>", self.open_history_result)
        self.history_empty = label(box, "No analysis runs yet.\nImport a memory image to start an investigation.",
                                   10, MUTED, bg=CARD, justify="center")
        self.history_empty.place(relx=0.5, rely=0.56, anchor="center")
        label(page, "LOCAL EVIDENCE  /  RECORDED COMMANDS  /  SEPARATE ARTIFACTS",
              8, MUTED, font=(MONO, 8)).pack(side="bottom", anchor="w", pady=(14, 0), before=box)

    def _analysis(self):
        outer = self.pages["Analyze"]
        self.mode_tabs = ttk.Notebook(outer)
        self.mode_tabs.pack(fill="both",expand=True)
        self.guided_plan=frame(self.mode_tabs)
        self.advanced_plan=frame(self.mode_tabs)
        self.mode_tabs.add(self.guided_plan,text="Investigation goals")
        self.mode_tabs.add(self.advanced_plan,text="Advanced plugins")
        page = self.advanced_plan
        page.columnconfigure(0, weight=1)
        page.columnconfigure(1, weight=1)
        page.rowconfigure(1, weight=1)
        self.planner_header(page).grid(row=0,column=0,columnspan=2,sticky="ew",pady=(0,14))
        left = frame(page)
        left.grid(row=1,column=0,sticky="nsew",padx=(0,16))
        self.plugin_search = tk.StringVar()
        self.plugin_search.trace_add("write",lambda *_:self.filter_plugins())
        search=frame(left);search.pack(fill="x",pady=(0,8))
        ttk.Entry(search,textvariable=self.plugin_search).pack(side="left",fill="x",expand=True)
        self.plugin_family=tk.StringVar(value="Windows")
        family=ttk.Combobox(search,textvariable=self.plugin_family,state="readonly",width=11,
                            values=["All","Windows","Linux","macOS","Generic"])
        family.pack(side="left",padx=(8,0))
        family.bind("<<ComboboxSelected>>",lambda _:self.filter_plugins())
        controls=frame(left);controls.pack(fill="x",pady=(0,8))
        button(controls,"Check shown",self.select_shown).pack(side="left")
        button(controls,"Clear",self.clear_checked).pack(side="left",padx=8)
        button(controls,"Review selection",self.review_checked).pack(side="left")
        button(controls,"Refresh",self.refresh_catalog).pack(side="right")
        self.checkbox_images()
        box,self.plugin_tree=table(left,("Installed plugin",),[390],height=8)
        self.plugin_tree.configure(show="tree headings")
        self.plugin_tree.column("#0",width=46,minwidth=46,stretch=False)
        self.plugin_tree.heading("#0",text="Use",anchor="center")
        box.pack(fill="both",expand=True)
        self.plugin_tree.bind("<<TreeviewSelect>>",self.select_plugin)
        self.plugin_tree.bind("<Button-1>",self.toggle_plugin_event,add="+")
        self.plugin_tree.bind("<space>",self.toggle_selected_plugin)
        self.plugin_count=label(left,"Discovering installed plugins...",9,MUTED,wraplength=390,justify="left")
        self.plugin_count.pack(fill="x",pady=(8,0))
        right=frame(page);right.grid(row=1,column=1,sticky="nsew")
        self.plugin_title=label(right,"Select a plugin to inspect its options",14,bold=True,wraplength=520,justify="left")
        self.plugin_title.pack(fill="x",pady=(0,8))
        self.plugin_description=label(right,"Check a plugin on the left to include it. Click its name to configure it.",9,MUTED,wraplength=520,justify="left")
        self.plugin_description.pack(fill="x",pady=(0,10))
        for widget in (self.plugin_title,self.plugin_description):
            widget.bind("<Configure>",lambda e,w=widget:w.configure(wraplength=max(240,e.width)))
        bottom=frame(right);bottom.pack(side="bottom",fill="x",pady=(8,0))
        button(bottom,"Save options",self.save_plugin_options).pack(side="left")
        button(bottom,"Run this plugin",self.run_selected).pack(side="right")
        scroll_holder=frame(right);scroll_holder.pack(fill="both",expand=True)
        self.option_canvas=tk.Canvas(scroll_holder,bg=BG,highlightthickness=0)
        scroll=ttk.Scrollbar(scroll_holder,orient="vertical",command=self.option_canvas.yview)
        self.option_canvas.configure(yscrollcommand=scroll.set)
        self.option_canvas.pack(side="left",fill="both",expand=True);scroll.pack(side="right",fill="y")
        self.options_frame=frame(self.option_canvas)
        self.option_window=self.option_canvas.create_window(0,0,anchor="nw",window=self.options_frame)
        self.options_frame.bind("<Configure>",lambda _:self.option_canvas.configure(scrollregion=self.option_canvas.bbox("all")))
        self.option_canvas.bind("<Configure>",self.resize_options)
        # Queue methods remain usable by integrations; the checked plan is the primary UI.
        self.queue_label=label(right,"ANALYSIS QUEUE / 0")
        self.queue_list=tk.Listbox(right,height=3)

        self.build_guided(self.guided_plan)

    def _results(self):
        page = self.pages["Results"]
        top = frame(page)
        top.pack(fill="x", pady=(0, 8))
        self.run_selector = ttk.Combobox(top, state="readonly")
        self.run_selector.pack(side="left", fill="x", expand=True)
        self.run_selector.bind("<<ComboboxSelected>>", self.choose_run)
        button(top, "Run folder", self.open_run_folder).pack(side="right", padx=(8, 0))
        self.result_notice = label(page, "Import a capture and run analysis. Reports include failures, not just findings.",
                                   9, MUTED, justify="left", wraplength=950)
        self.result_notice.pack(fill="x", pady=(0, 10))
        self.result_notice.bind("<Configure>", lambda e: self.result_notice.configure(wraplength=max(350,e.width)))
        self.result_tabs = ttk.Notebook(page)
        self.result_tabs.pack(fill="both", expand=True)
        data_page, log_page, details_page = frame(self.result_tabs), frame(self.result_tabs), frame(self.result_tabs)
        self.diagnosis_page, self.observables_page, self.search_page = (frame(self.result_tabs) for _ in range(3))
        for item, title in ((data_page,"Result table"),(log_page,"Execution log"),
                            (self.diagnosis_page,"Diagnostics"),(self.observables_page,"Observables"),
                            (self.search_page,"Search case"),(details_page,"Run metadata")):
            self.result_tabs.add(item,text=title)
        filter_row = frame(data_page); filter_row.pack(fill="x", pady=8)
        self.result_filter = tk.StringVar()
        entry=ttk.Entry(filter_row,textvariable=self.result_filter); entry.pack(side="left",fill="x",expand=True)
        entry.bind("<Return>",lambda _: self.load_result(reset=True))
        button(filter_row,"Filter this table",lambda: self.load_result(reset=True)).pack(side="left",padx=(8,0))
        box,self.result_tree=table(data_page,("Result",),[500],height=7); box.pack(fill="both",expand=True)
        self.result_tree.bind("<Double-1>",self.view_row)
        self.result_empty=label(box,"No analysis result selected.",10,MUTED,bg=CARD,justify="center",wraplength=650)
        self.result_empty.place(relx=.5,rely=.5,anchor="center")
        paging=frame(data_page); paging.pack(side="bottom",fill="x",pady=6,before=box)
        button(paging,"Previous",lambda: self.turn_page(-1)).pack(side="left")
        button(paging,"Next",lambda: self.turn_page(1)).pack(side="left",padx=6)
        self.page_label=label(paging,"0 rows",9,MUTED); self.page_label.pack(side="left",padx=8)
        self.log_text=readonly_text(log_page); self.log_text.pack(fill="both",expand=True,pady=8)
        self.detail_text=readonly_text(details_page); self.detail_text.pack(fill="both",expand=True,pady=8)
        diagnostic_actions=frame(self.diagnosis_page); diagnostic_actions.pack(fill="x",pady=8)
        button(diagnostic_actions,"Copy diagnostics",self.copy_diagnostics).pack(side="left")
        button(diagnostic_actions,"Symbols / settings",lambda: self.show("Settings")).pack(side="left",padx=8)
        button(diagnostic_actions,"Retry analysis",self.run_triage,True).pack(side="right")
        self.diagnosis_text=readonly_text(self.diagnosis_page); self.diagnosis_text.pack(fill="both",expand=True,pady=(0,8))
        actions=frame(page); actions.pack(side="bottom",fill="x",pady=(10,0),before=self.result_tabs)
        button(actions,"Bookmark row",self.bookmark).pack(side="left")
        self.csv_button=button(actions,"Export this table (CSV)",lambda: self.export_table("csv"))
        self.csv_button.pack(side="left",padx=8)
        self.csv_button.configure(state="disabled")
        button(actions,"Export PDF / HTML / CSV",self.report,True).pack(side="right")

    def _hunt(self):
        page = self.search_page
        label(page, "Search across the case", 17, bold=True).pack(anchor="w")
        label(page, "Find a literal IP, domain, process name, command, or other text in completed indexes.\n"
              "This searches plugin output, not every byte of the memory image. Use YARA plugins for memory scanning.",
              10, MUTED, justify="left", wraplength=950).pack(anchor="w", pady=(12, 22))
        row = frame(page)
        row.pack(fill="x")
        self.hunt_query = tk.StringVar()
        search = ttk.Entry(row, textvariable=self.hunt_query)
        search.pack(side="left", fill="x", expand=True)
        search.bind("<Return>", lambda _: self.hunt())
        button(row, "Search case", self.hunt, True).pack(side="left", padx=(10, 0))
        self.hunt_count = label(page, "No search has been run.", 9, MUTED)
        self.hunt_count.pack(anchor="w", pady=16)
        box, self.hunt_tree = table(page, ("Plugin", "Row", "Matched record"), [290, 60, 580])
        box.pack(fill="both", expand=True)
        self.hunt_tree.bind("<Double-1>", self.view_hunt_row)
        label(page, "Matches are leads for investigation, not proof of malicious activity. Maximum display: 500 rows.",
              9, MUTED).pack(anchor="w", pady=14)

    def _notes(self):
        page = self.pages["Case notes"]
        label(page, "Record your assessment", 17, bold=True).pack(anchor="w")
        label(page, "Separate observed evidence from interpretation. Notes and bookmarks are included in the case report.",
              10, MUTED, wraplength=950).pack(anchor="w", pady=(10, 18))
        self.note_input = tk.Text(page, height=5, bg=INPUT, fg=TEXT, insertbackground=TEXT,
                                  font=(FONT, 10), wrap="word", padx=14, pady=12,
                                  relief="flat", highlightthickness=1, highlightbackground=BORDER)
        self.note_input.pack(fill="x")
        row = frame(page)
        row.pack(fill="x", pady=12)
        button(row, "Save case note", self.save_note, True).pack(side="left")
        button(row, "Verify audit chain", self.check_audit).pack(side="right")
        self.notes_text = readonly_text(page)
        self.notes_text.pack(fill="both", expand=True)

    def _settings_page(self):
        page = self.pages["Settings"].body
        label(page, "Analysis configuration", 17, bold=True).pack(anchor="w")
        label(page, "Symbol lookup is controlled explicitly. The application does not upload your memory image.",
              10, MUTED, wraplength=950).pack(anchor="w", pady=(10, 20))
        label(page, "Symbol directory (parent of windows / linux / mac)", 10, bold=True).pack(anchor="w")
        row = frame(page)
        row.pack(fill="x", pady=10)
        self.symbols_var = tk.StringVar(value=self.settings.symbols)
        ttk.Entry(row, textvariable=self.symbols_var).pack(side="left", fill="x", expand=True)
        button(row, "Browse", self.pick_symbols).pack(side="left", padx=(10, 0))
        button(row, "Open folder", self.open_symbols).pack(side="left", padx=(10, 0))
        label(page, "Linux requires an ISF matching the exact captured kernel banner. Windows can obtain missing symbols\n"
              "from symbol servers when offline mode is disabled. Imported symbol files must come from a trusted source.",
              9, MUTED, justify="left", wraplength=960).pack(anchor="w", pady=(0, 10))
        import_row = frame(page)
        import_row.pack(fill="x", pady=(0, 15))
        self.symbol_os = tk.StringVar(value="linux")
        ttk.Combobox(import_row, textvariable=self.symbol_os, values=["linux", "windows", "mac"],
                     state="readonly", width=12).pack(side="left")
        button(import_row, "Import symbol file", self.import_symbol).pack(side="left", padx=10)
        self.offline_var = tk.BooleanVar(value=self.settings.offline)
        self.verify_var = tk.BooleanVar(value=self.settings.verify_after_batch)
        ttk.Checkbutton(page, text="Offline symbols - disable automatic network symbol lookup", variable=self.offline_var).pack(anchor="w", pady=5)
        ttk.Checkbutton(page, text="Recalculate the full image SHA-256 after each analysis batch", variable=self.verify_var).pack(anchor="w", pady=5)
        self.auto_export_var = tk.BooleanVar(value=self.settings.auto_export)
        ttk.Checkbutton(page, text="Automatically generate PDF, HTML and CSV reports after analysis", variable=self.auto_export_var).pack(anchor="w", pady=5)
        timeout_row = frame(page)
        timeout_row.pack(fill="x", pady=12)
        label(timeout_row, "Plugin timeout (seconds, 0 = unlimited)", 10).pack(side="left")
        self.timeout_var = tk.StringVar(value=str(self.settings.timeout_seconds))
        ttk.Entry(timeout_row, textvariable=self.timeout_var, width=12).pack(side="left", padx=15)
        button(timeout_row, "Save settings", self.save_settings, True).pack(side="right")
        row = frame(page)
        row.pack(fill="x", pady=(15, 10))
        label(row, "Engine diagnostics", 13, bold=True).pack(side="left")
        button(row, "Refresh engine", self.refresh_catalog).pack(side="right")
        self.diagnostics = readonly_text(page, height=8)
        self.diagnostics.pack(fill="both", expand=True)
        label(page, f"Local case and configuration storage: {data_root()}", 9, MUTED,
              wraplength=950, justify="left").pack(side="bottom", anchor="w", pady=(14, 0), before=self.diagnostics)

    def show(self, name):
        self.active_page = name
        if hasattr(self,"export_last_row"):
            if name in ("Overview","Findings","Results","Evidence lab"):
                self.export_last_row.pack(fill="x",padx=20,pady=(0,10))
            else:
                self.export_last_row.pack_forget()
        self.pages[name].tkraise()
        if hasattr(self,"goal_cards"):
            self.refresh_guided()
        self.heading.configure(text={"Overview":"Case workspace","Analyze":"Investigate","Execution":"Live run","Findings":"Findings & reports","Results":"Evidence tables","Case notes":"Analyst notes"}.get(name,name))
        subtitles = {"Overview": "Evidence first. Analysis in context.",
                     "Analyze": "Choose a goal. Run a documented plan. Review the evidence.",
                     "Execution": "Live engine output. Transparent progress. Original logs preserved.",
                     "Findings": "Specific evidence. Explicit limits. No automatic malware verdict.",
                     "Results": "Review the evidence. Preserve the context.",
                     "Evidence lab": "Collect bytes. Preserve time semantics. Correlate supplied evidence.",
                     "IOC search": "Connect an indicator to the artifacts already recovered.",
                     "Case notes": "Document observations, questions and decisions.",
                     "Settings": "Control symbols, connectivity and verification."}
        self.subheading.configure(text=subtitles[name])
        for key, nav in self.nav_buttons.items():
            nav.configure(bg=CARD if key == name else SIDE,
                          fg=TEXT if key == name else MUTED)
            self.nav_markers[key].configure(bg=RED if key == name else SIDE)
        if name == "Evidence lab":
            self.refresh_lab()
        if name == "Case notes" and self.case and not self.busy:
            self.refresh_notes()

    def _set_busy(self, value):
        self.busy = value
        self.refresh_guided()
        self.cancel_button.configure(state="normal" if value else "disabled")
        if value:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)

    def idle_required(self):
        if self.busy:
            messagebox.showinfo("Task in progress", "Finish or cancel the current task before starting another.", parent=self)
            return False
        return True

    def case_required(self):
        if not self.idle_required():
            return False
        if self.case is None:
            messagebox.showinfo("No case open", "Import a memory image or open an existing case first.", parent=self)
            return False
        return True

    def task(self, function, callback=None, text="Working..."):
        if not self.idle_required():
            return
        self.cancel_event = threading.Event()
        self._set_busy(True)
        self.status_var.set(text)
        def execute():
            try:
                value = function(self.cancel_event, self.emit)
                self.events.put(("task_done", (callback, value, None)))
            except Exception as exc:
                self.events.put(("task_done", (callback, None, exc)))
        threading.Thread(target=execute, daemon=True, name="ts007-task").start()

    def emit(self, event, value):
        self.events.put((event, value))

    def _poll(self):
        try:
            for _ in range(50):
                event, payload = self.events.get_nowait()
                if event == "task_done":
                    callback, value, error = payload
                    self._set_busy(False)
                    self.phase_progress.stop()
                    if self.execution_plan:
                        for key in self.execution_plan[self.execution_done:]:
                            if self.execution_tree.exists(key):
                                values=list(self.execution_tree.item(key,"values"));values[1]="Not run"
                                self.execution_tree.item(key,values=values)
                    if error:
                        self.status_var.set(str(error))
                        if not isinstance(error, Cancelled) and not self.closing:
                            messagebox.showerror("Operation not completed", str(error), parent=self)
                    elif callback:
                        callback(value)
                    else:
                        self.status_var.set("Operation completed.")
                    if self.closing:
                        self._close_now()
                        return
                elif event == "catalog":
                    self.catalog_loading = False
                    self.catalog = payload
                    self.catalog_error = ""
                    self.filter_plugins()
                    if not self.checked_plugins and not self.busy:
                        self.apply_profile(quiet=True)
                    self.update_diagnostics()
                    if not self.busy:
                        self.status_var.set(f"Volatility ready / {len(payload['plugins'])} available plugins.")
                elif event == "catalog_error":
                    self.catalog_loading = False
                    self.catalog_error = str(payload)
                    self.plugin_count.configure(text="Engine unavailable. Open Settings for installation details.")
                    self.update_diagnostics()
                    if not self.busy:
                        self.status_var.set("Engine setup required. The case manager remains available.")
                elif event == "hash_progress":
                    self.progress.stop()
                    self.progress.configure(mode="determinate", value=float(payload))
                    self.status_var.set(f"Reading image for SHA-256 verification: {payload:.1f}%")
                elif event == "status":
                    self.status_var.set(str(payload))
                    self.phase_var.set(str(payload))
                elif event == "run_log":
                    self.append_live(payload)
                elif event == "run_progress":
                    self.status_var.set(f"Running {payload['plugin']} / {payload['elapsed']:.0f} seconds")
                    self.live_progress(payload)
                elif event == "run_started":
                    self.progress.configure(mode="indeterminate")
                    self.progress.start(12)
                    self.selected_run = payload["id"]
                    self.live_started(payload)
                    self.refresh_case()
                elif event == "run_finished":
                    self.live_finished(payload)
                    self.status_var.set(f"{payload['plugin']}: {payload['status']} / {payload['rows']} rows")
                    self.refresh_case()
        except queue.Empty:
            pass
        except Exception as exc:
            self.status_var.set(f"Interface error: {exc}")
            if not self.closing:
                messagebox.showerror("Interface error", str(exc), parent=self)
        self.refresh_guided()
        self.after(100, self._poll)

    def refresh_catalog(self):
        if getattr(self, "catalog_loading", False):
            return
        self.catalog_loading = True
        self.engine_badge.set("VOLATILITY 3 / CHECKING")
        self.plugin_count.configure(text="Discovering installed plugins...")
        def work():
            try:
                self.emit("catalog", discover_plugins())
            except Exception as exc:
                self.emit("catalog_error", str(exc))
        threading.Thread(target=work, daemon=True, name="ts007-catalog").start()

    def update_diagnostics(self):
        self.engine_badge.set("VOLATILITY 3 / SETUP REQUIRED" if self.catalog_error else
                              f"VOLATILITY READY / {len(self.catalog['plugins'])} PLUGINS")
        detail = {"app_version": __version__, "volatility_version": self.catalog["version"],
                  "available_plugins": len(self.catalog["plugins"]),
                  "unavailable_plugins": self.catalog["unavailable"],
                  "error": self.catalog_error,
                  "installation": 'python -m pip install -e ".[analysis]"',
                  "command_line_diagnostics": "python -m test_subject_007 --doctor"}
        put_text(self.diagnostics, json.dumps(detail, indent=2))

    def filter_plugins(self):
        term = self.plugin_search.get().casefold()
        family = self.plugin_family.get()
        prefixes = {"Windows": "windows.", "Linux": "linux.", "macOS": "mac."}
        self.plugin_tree.delete(*self.plugin_tree.get_children())
        for plugin in self.catalog["plugins"]:
            name = plugin["name"]
            if term and term not in (name + " " + plugin["description"]).casefold():
                continue
            if family in prefixes and not name.startswith(prefixes[family]):
                continue
            if family == "Generic" and name.split(".")[0] in ("windows", "linux", "mac"):
                continue
            self.plugin_tree.insert("", "end", iid=name, values=(name,), image=self.checked_image if name in self.checked_plugins else self.unchecked_image)
        self.plugin_count.configure(text=f"{len(self.plugin_tree.get_children())} shown / {len(self.catalog['plugins'])} available")

    def select_plugin(self, _=None):
        self.capture_plugin_options()
        selection = self.plugin_tree.selection()
        if not selection:
            return
        plugin = next(p for p in self.catalog["plugins"] if p["name"] == selection[0])
        self.current_plugin = plugin
        self.plugin_title.configure(text=plugin["name"])
        self.plugin_description.configure(text=plugin["description"][:900])
        for child in self.options_frame.winfo_children():
            child.destroy()
        self.option_vars = {}
        for spec in plugin["options"]:
            default = spec.get("default")
            if spec["kind"] == "bool":
                variable = tk.BooleanVar(value=bool(default))
                ttk.Checkbutton(self.options_frame, text=spec["flag"] + (" *" if spec["required"] else ""),
                                variable=variable).pack(anchor="w", pady=(8, 3))
            else:
                label(self.options_frame, spec["flag"] + (" *" if spec["required"] else ""),
                      10, bold=True).pack(anchor="w", pady=(10, 6))
                if isinstance(default, list):
                    default = json.dumps(default)
                variable = tk.StringVar(value="" if default is None else str(default))
                row = frame(self.options_frame)
                row.pack(fill="x", padx=(0, 8))
                if spec["kind"] == "choice":
                    control = ttk.Combobox(row, textvariable=variable, values=spec["choices"], state="readonly")
                else:
                    control = ttk.Entry(row, textvariable=variable)
                control.pack(side="left", fill="x", expand=True)
                if spec.get("is_file"):
                    button(row, "Browse", lambda v=variable: self.pick_option_file(v)).pack(side="left", padx=(8, 0))
            description = spec["description"]
            if spec["kind"] == "list":
                description += '  Use commas or a JSON array, e.g. [4, 128].'
            label(self.options_frame, description, 9, MUTED, justify="left", wraplength=560).pack(anchor="w", pady=(0, 8))
            self.option_vars[spec["name"]] = variable
        if not plugin["options"]:
            label(self.options_frame, "No additional options are required.\nVolatility resolves compatible layers and symbols automatically.",
                  10, MUTED, justify="left", wraplength=570).pack(anchor="w", pady=20)
        for name, value in self.saved_plugin_values.get(plugin["name"],{}).items():
            if name in self.option_vars:
                self.option_vars[name].set(value)
        if ".printkey." in plugin["name"] and self.profile_var.get() in ("Persistence investigation","Java and script investigation","Suspicious execution investigation","Complete forensic investigation"):
            label(self.options_frame,"Preset: four Run / RunOnce queries across recoverable hives. Saving a custom key overrides that expansion.",9,MUTED,wraplength=420,justify="left").pack(anchor="w",pady=10)
        self._options_dirty = False
        for variable in self.option_vars.values():
            variable.trace_add("write", self.mark_plugin_options_dirty)
        self.option_canvas.yview_moveto(0)

    def resize_options(self, event):
        self.option_canvas.itemconfigure(self.option_window,width=event.width)
        for child in self.options_frame.winfo_children():
            if isinstance(child,tk.Label):
                child.configure(wraplength=max(180,event.width-20))

    def pick_option_file(self, variable):
        path = filedialog.askopenfilename(parent=self, title="Select plugin input file")
        if path:
            variable.set(path)

    def current_selection(self):
        if not self.current_plugin:
            raise ValueError("Choose a plugin from the library first.")
        values = {key: variable.get() for key, variable in self.option_vars.items()}
        return self.current_plugin, plugin_arguments(self.current_plugin, values)

    def add_to_queue(self):
        try:
            plugin, arguments = self.current_selection()
            self.queue_items.append((plugin, arguments))
            self.queue_list.insert("end", plugin["name"] + "  " + " ".join(arguments))
            self.queue_label.configure(text=f"ANALYSIS QUEUE  /  {len(self.queue_items)}")
        except Exception as exc:
            messagebox.showerror("Plugin options", str(exc), parent=self)

    def clear_queue(self):
        self.queue_items.clear()
        self.queue_list.delete(0, "end")
        self.queue_label.configure(text="ANALYSIS QUEUE  /  0")

    def run_selected(self):
        try:
            plugin, arguments = self.current_selection()
            self.run_batch([(plugin, arguments)])
        except Exception as exc:
            messagebox.showerror("Plugin options", str(exc), parent=self)

    def run_queue(self):
        if not self.queue_items:
            messagebox.showinfo("Empty queue", "Select a plugin and use Add to queue.", parent=self)
            return
        self.run_batch(list(self.queue_items))

    def run_triage(self):
        if not self.case_required():
            return
        if not self.catalog["plugins"]:
            self.show("Settings")
            messagebox.showinfo("Engine not ready","Install the engine and refresh diagnostics.",parent=self)
            return
        self.apply_profile(quiet=True)
        self.show("Analyze")
        self.status_var.set("Review the checked investigation plugins, then click Start checked plugins.")

    def run_batch(self, items, triage=False, preflight=None):
        if not self.case_required():
            return
        if not self.catalog["plugins"]:
            messagebox.showerror("Engine unavailable","Open Settings and install the analysis dependencies.",parent=self)
            return
        try:
            settings=self.settings.normalized()
            output=user_path(self.export_dir_var.get())
            from .exporting import safe_destination
            safe_destination(self.case,output/"destination-check.txt")
            self.case.check_source()
            inspect_image(self.case.image)
        except Exception as exc:
            messagebox.showerror("Pre-analysis check",str(exc),parent=self)
            return
        case=self.case
        version=self.catalog["version"]
        if preflight is None:
            preflight = {"selected_plugins": list(dict.fromkeys(p["name"] for p,a in items)),
                         "ready_jobs": [{"plugin":p["name"],"arguments":a} for p,a in items],
                         "deferred":[], "unavailable":[], "notices":[]}
            case.metadata.update(investigation_profile="Custom", profile_missing=[])
        self.prepare_execution(items, preflight)
        def work(cancel,emit):
            completed=[]
            requested=[p["name"] for p,args in items]
            case.metadata["last_batch"]={"requested":requested,"guided":triage,
                "jobs":[{"plugin":p["name"],"arguments":a} for p,a in items],
                "preflight":preflight, "preflight_not_run":preflight.get("deferred",[])}
            case.metadata["preflight"] = preflight
            case.save()
            case.audit("investigation_plan_accepted", preflight)
            for plugin,arguments in items:
                if cancel.is_set():
                    break
                result=run_plugin(case,plugin["name"],arguments,settings,version,cancel,emit)
                completed.append(result)
                if result["status"] in ("cancelled","integrity_warning"):
                    break
                gate=plugin["name"].rsplit(".",1)[0] in ("windows.info","linux.pslist","mac.pslist")
                if triage and gate and result["status"] not in ("completed","completed_with_warnings"):
                    emit("status","Analysis stopped at the image/symbol check. Diagnostics will explain the failure.")
                    break
            verification="Not requested"
            if settings.verify_after_batch and not cancel.is_set():
                emit("status","Verifying the source image after analysis...")
                okay=case.verify_image(cancel,lambda p: emit("hash_progress",p))
                verification="SHA-256 matched" if okay else "SHA-256 MISMATCH"
            elif cancel.is_set():
                verification="Cancelled; verify evidence before finalizing the case"
            case.metadata["last_batch"]["executed"]=[r["id"] for r in completed]
            case.metadata["last_batch"]["not_run"]=requested[len(completed):]
            case.save()
            case.audit("batch_finished",{"requested":len(items),"executed":len(completed),"verification":verification})
            bundle=None; export_error=""
            if not cancel.is_set():
                try:
                    if settings.auto_export:
                        bundle=export_bundle(case,output,cancel,emit)
                    else:
                        summary=build_summary(case,cancel,emit)
                        atomic_json(case.root/"analysis-summary.json",summary)
                except Exception as exc:
                    export_error=str(exc)
            return completed,verification,len(items),bundle,export_error
        def done(value):
            runs,verification,requested,bundle,export_error=value
            self.refresh_case()
            if bundle:
                self._export_completed(bundle)
            self.refresh_observables()
            self.refresh_findings(bundle.get("summary") if bundle else None)
            if runs:
                self.selected_run=runs[-1]["id"]
                self.refresh_runs(); self.load_result()
            if export_error:
                messagebox.showerror("Analysis saved; report export needs attention",export_error,parent=self)
            gap = len(preflight.get("deferred",[])) + len(preflight.get("unavailable",[]))
            self.phase_var.set(f"{len(runs)} of {requested} queued tasks finished. {gap} deferred/unavailable. {verification}.")
            self.execution_title.set("Investigation finished" if len(runs)==requested and not gap else "Investigation finished / partial coverage")
            self.show("Findings" if any(r["status"] in ("completed","completed_with_warnings") for r in runs) else "Results")
            self.status_var.set(f"Analysis: {len(runs)}/{requested} runs. {verification}. " +
                                ("Reports saved; see the folder below." if bundle else "Use Export PDF / HTML / CSV to generate reports."))
        self.task(work,done,"Preparing analysis...")

    def import_memory(self):
        if not self.idle_required():
            return
        dialog=ImportDialog(self, self.settings, self.export_dir_var.get())
        self.wait_window(dialog)
        values=dialog.result
        if not values:
            return
        self.settings=replace(self.settings, offline=not values["online"],
                              export_dir=values["exports"], auto_export=values["auto_export"])
        atomic_json(data_root()/"settings.json",asdict(self.settings))
        self.offline_var.set(self.settings.offline)
        self.auto_export_var.set(self.settings.auto_export)
        self.export_dir_var.set(values["exports"])
        def work(cancel,emit):
            case=Case.create(Path(values["base"]),Path(values["image"]),values["name"],values["analyst"],
                             values["os"],cancel,lambda p: emit("hash_progress",p))
            case.metadata["export_directory"]=values["exports"]
            case.save()
            return case
        def done(case):
            self.install_case(case)
            if self.catalog["plugins"]:
                self.apply_profile(quiet=True)
                self.show("Analyze")
                self.mode_tabs.select(self.guided_plan)
                self.status_var.set("Image imported and hashed. Choose an investigation goal, then run.")
            else:
                self.status_var.set("Case imported and hashed. Engine setup is required before analysis can start.")
                self.show("Settings")
        self.task(work,done,"Hashing the selected image; the original is not copied or changed...")

    def open_case(self):
        if not self.idle_required():
            return
        path = filedialog.askdirectory(parent=self, title="Open case folder", initialdir=str(workspace_root() / "Cases"))
        if path:
            self.open_case_path(path)

    def open_case_path(self, path):
        if self.case and Path(path).resolve() == self.case.root:
            return
        self.task(lambda *_: Case.open(Path(path)), self.install_case, "Opening and checking the case audit chain...")

    def install_case(self, case):
        if self.case:
            self.case.close()
        self.case = case
        self.export_dir_var.set(case.metadata.get("export_directory",self.settings.export_dir or str(workspace_root()/"Reports")))
        exports=recover_last_exports(case)
        self.last_export_folder=Path(next(iter(exports.values()))).parent if exports else None
        self.last_export_var.set(str(self.last_export_folder) if self.last_export_folder else "No report export recorded for this case.")
        self.observable_tree.delete(*self.observable_tree.get_children())
        self.observable_records={}
        self.observable_filter.set("")
        self.refresh_observables()
        self.csv_button.configure(state="disabled")
        put_text(self.diagnosis_text,"")
        self.selected_run = ""
        self.page_number = 0
        self.current_rows = {}
        self.hunt_rows = {}
        self.result_tree.delete(*self.result_tree.get_children())
        self.hunt_tree.delete(*self.hunt_tree.get_children())
        self.result_filter.set("")
        self.hunt_query.set("")
        self.hunt_count.configure(text="No search has been run for this case.")
        self.page_label.configure(text="0 rows")
        self.result_notice.configure(text="Select an analysis run from this case.")
        put_text(self.log_text, "")
        put_text(self.detail_text, "")
        self.note_input.delete("1.0", "end")
        self.clear_queue()
        self.refresh_findings()
        self.live_blocks.clear()
        self.render_live()
        self.execution_plan=[]
        self.execution_tree.delete(*self.execution_tree.get_children())
        self.execution_title.set("No analysis in progress")
        self.checked_plugins.clear()
        self.saved_plugin_values.clear()
        self.terms_var.set(", ".join(case.metadata.get("investigation_terms",[])))
        previous=case.metadata.get("investigation_profile")
        from .profiles import DESCRIPTIONS
        if previous in DESCRIPTIONS:self.profile_var.set(previous)
        if self.catalog["plugins"]:
            self.apply_profile(quiet=True)
        self.refresh_case()
        self.refresh_notes()
        self.show("Overview")
        self.status_var.set(f"Case open: {case.metadata['name']}")

    def refresh_case(self):
        if not self.case:
            return
        meta = self.case.metadata
        self.title(f"Test Subject 007 | {meta['name']}")
        for item in self.case_buttons:
            item.configure(state="normal")
        self.metrics["os"].configure(text=meta["evidence_os"])
        self.metrics["size"].configure(text=human_size(meta["fingerprint"]["size"]))
        self.metrics["hash"].configure(text="MISMATCH" if meta.get("verification") == "mismatch" else "Recorded",
                                       fg=WARN if meta.get("verification") == "mismatch" else GOOD)
        self.metrics["runs"].configure(text=str(len(self.case.runs())))
        self.hero_title.configure(text=meta["name"][:60])
        self.hero_detail.configure(text=f"Image: {meta['image']}\nAnalyst: {meta['analyst']}  /  Last full verification: {meta.get('last_verified_utc', 'Not recorded')}")
        self.hash_var.set(meta["sha256"])
        self.refresh_runs()

    def refresh_runs(self):
        if not self.case:
            return
        self.run_items = self.case.runs()
        if self.run_items:
            self.history_empty.place_forget()
        else:
            self.history_empty.place(relx=0.5, rely=0.56, anchor="center")
        self.history.delete(*self.history.get_children())
        for i, run in enumerate(self.run_items):
            self.history.insert("", "end", iid=run["id"], values=(run["plugin"], run["status"],
                                run.get("rows", 0), run["started_utc"]), tags=("alternate",) if i % 2 else ())
        self.run_selector.configure(values=[f"{r['started_utc']}  |  {r['plugin']}  |  {r['status']}" for r in self.run_items])
        if self.run_items:
            index = next((i for i, r in enumerate(self.run_items) if r["id"] == self.selected_run), 0)
            self.run_selector.current(index)
            self.selected_run = self.run_items[index]["id"]
        else:
            self.run_selector.set("")
            self.selected_run = ""

    def verify_image(self):
        if not self.case_required():
            return
        case = self.case
        def done(matched):
            self.refresh_case()
            self.status_var.set("SHA-256 verification matched the import hash." if matched else "SHA-256 MISMATCH. Further analysis is blocked.")
            if not matched:
                messagebox.showerror("Evidence changed", "The current image no longer matches the import hash. Preserve both versions and investigate.", parent=self)
        self.task(lambda cancel, emit: case.verify_image(cancel, lambda p: emit("hash_progress", p)), done,
                  "Verifying the full evidence image...")

    def relink_image(self):
        if not self.case_required():
            return
        path = filedialog.askopenfilename(parent=self, title="Select the relocated image (hash must match)")
        if not path:
            return
        case = self.case
        def done(matched):
            self.refresh_case()
            self.status_var.set("Image relinked; full SHA-256 matched." if matched else "Relink refused: SHA-256 does not match. Original reference retained.")
        self.task(lambda cancel, emit: case.verify_image(cancel, lambda p: emit("hash_progress", p), Path(path)), done)

    def choose_run(self, _=None):
        if self.busy:
            return
        index = self.run_selector.current()
        if 0 <= index < len(self.run_items):
            self.selected_run = self.run_items[index]["id"]
            self.result_filter.set("")
            self.load_result(reset=True)

    def open_history_result(self, _=None):
        if self.busy:
            return
        selected = self.history.selection()
        if selected:
            self.selected_run = selected[0]
            self.refresh_runs()
            self.result_filter.set("")
            self.show("Results")
            self.load_result(reset=True)

    def load_result(self, reset=False):
        if not self.case or not self.selected_run or self.busy:
            return
        if reset:
            self.page_number=0
        case,run_id,query,page=self.case,self.selected_run,self.result_filter.get(),self.page_number
        folder=case.root/"runs"/run_id
        def work(*_):
            run=json.loads((folder/"run.json").read_text(encoding="utf-8"))
            log=collect_log(folder)
            diagnostic=diagnose(run,text=log)
            columns,rows,total=query_rows(folder/"results.sqlite",query,page)
            # Older cases may have indexed an error line as a header. Do not display it as evidence.
            if columns and columns[0]!="TreeDepth":
                columns,rows,total=[],[],0
            return run,(columns,rows,total),log,diagnostic
        def done(value):
            run,(columns,rows,total),log,diagnostic=value
            self.current_rows=dict(rows)
            self.result_tree.delete(*self.result_tree.get_children())
            self.result_tree.configure(columns=columns or ["Result"])
            for column in columns or ["Result"]:
                self.result_tree.heading(column,text=column,command=lambda c=column: self.sort_current_page(c))
                self.result_tree.column(column,width=180,minwidth=70,stretch=False)
            for index,(row_id,data) in enumerate(rows):
                self.result_tree.insert("","end",iid=str(row_id),values=[str(data.get(c,"")).replace("\n"," ")[:2000] for c in columns],tags=("alternate",) if index%2 else ())
            self.csv_button.configure(state="normal" if columns and run.get("rows",0)>0 else "disabled")
            if rows:
                self.result_empty.place_forget()
            else:
                empty=("No table was produced. Open Diagnostics for the engine error." if not columns else
                       "No matching rows. This does not establish that the captured system was clean.")
                self.result_empty.configure(text=empty)
                self.result_empty.place(relx=.5,rely=.5,anchor="center")
            self.page_label.configure(text=f"Page {page+1} / {max(1,(total+PAGE_SIZE-1)//PAGE_SIZE)} | {total:,} matching rows")
            self.result_notice.configure(text=f"{run['status'].upper()} / {run.get('rows',0):,} indexed records / {diagnostic['title']}")
            put_text(self.log_text,log)
            put_text(self.diagnosis_text,format_diagnosis(diagnostic)+"\n\nCASE RUN FOLDER\n"+str(folder))
            put_text(self.detail_text,json.dumps(run,indent=2,ensure_ascii=False))
            if run['status'] not in ("completed","completed_with_warnings"):
                self.result_tabs.select(self.diagnosis_page)
            elif not reset:
                self.result_tabs.select(0)
            self.status_var.set("Results loaded. Export destinations remain visible below.")
        self.task(work,done,"Reading result and original diagnostics...")

    def turn_page(self, delta):
        if self.busy:
            return
        self.page_number = max(0, self.page_number + delta)
        self.load_result()

    def sort_current_page(self, column):
        def key(item):
            value = str(self.current_rows.get(int(item), {}).get(column, ""))
            try:
                return (0, int(value, 16) if value.lower().startswith("0x") else float(value))
            except ValueError:
                return (1, value.casefold())
        for index, item in enumerate(sorted(self.result_tree.get_children(), key=key)):
            self.result_tree.move(item, "", index)

    def show_record(self, title, record):
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("850x560")
        dialog.configure(bg=BG)
        box = readonly_text(dialog)
        box.pack(fill="both", expand=True, padx=18, pady=18)
        put_text(box, json.dumps(record, indent=2, ensure_ascii=False))
        button(dialog, "Close", dialog.destroy).pack(pady=(0, 16))

    def view_row(self, _=None):
        selection = self.result_tree.selection()
        if selection and int(selection[0]) in self.current_rows:
            self.show_record(f"Result row {selection[0]}", self.current_rows[int(selection[0])])

    def bookmark(self):
        if not self.case_required():
            return
        selection = self.result_tree.selection()
        if not selection:
            messagebox.showinfo("Select a row", "Select a result row to bookmark.", parent=self)
            return
        text = simpledialog.askstring("Bookmark", "Record why this row matters:", parent=self)
        if text:
            try:
                self.case.add_note(text, self.selected_run, int(selection[0]))
                self.status_var.set("Bookmark saved to case notes.")
            except Exception as exc:
                messagebox.showerror("Bookmark", str(exc), parent=self)

    def export_table(self, mode="csv"):
        if not self.case_required() or not self.selected_run:
            return
        output=user_path(self.export_dir_var.get())
        output.mkdir(parents=True,exist_ok=True)
        path=filedialog.asksaveasfilename(parent=self,title="Export selected table as CSV",initialdir=str(output),
                                        initialfile=self.selected_run+".csv",defaultextension=".csv",filetypes=[("CSV","*.csv")])
        if path:
            case,run_id=self.case,self.selected_run
            def done(count):
                case.metadata['last_exports']={'csv':str(Path(path).resolve())}
                case.save()
                self.last_export_folder=Path(path).parent
                self.last_export_var.set(str(Path(path).resolve()))
                self.status_var.set(f"Exported {count:,} records. Copy or open the saved path below.")
                ExportDialog(self,{"csv":str(Path(path).resolve())})
            self.task(lambda *_: export_results(case,run_id,Path(path),"csv"),done,"Exporting all rows in the selected run...")

    def report(self):
        if not self.case_required():
            return
        try:
            destination=user_path(self.export_dir_var.get())
        except Exception as exc:
            messagebox.showerror("Report folder",str(exc),parent=self)
            return
        case=self.case
        self.task(lambda cancel,emit: export_bundle(case,destination,cancel,emit),
                  self._export_completed,"Generating PDF, HTML and CSV reports...")

    def hunt(self):
        if not self.case_required():
            return
        needle, case = self.hunt_query.get(), self.case
        def done(value):
            found, total = value
            self.hunt_rows = {str(i): record for i, record in enumerate(found)}
            self.hunt_tree.delete(*self.hunt_tree.get_children())
            for i, record in self.hunt_rows.items():
                self.hunt_tree.insert("", "end", iid=i, values=(record["plugin"], record["row_id"],
                                      json.dumps(record["record"], ensure_ascii=False)[:700]))
            self.hunt_count.configure(text=f"{total:,} matching records / showing {len(found):,}. Double-click for context.")
            self.status_var.set("Case search completed. Matches require analyst validation.")
        self.task(lambda cancel, _: hunt_case(case, needle, cancel=cancel), done, "Searching indexed plugin results...")

    def view_hunt_row(self, _=None):
        selected = self.hunt_tree.selection()
        if selected:
            self.show_record("IOC search match", self.hunt_rows[selected[0]])

    def save_note(self):
        if not self.case_required():
            return
        try:
            self.case.add_note(self.note_input.get("1.0", "end"))
            self.note_input.delete("1.0", "end")
            self.refresh_notes()
            self.status_var.set("Case note saved.")
        except Exception as exc:
            messagebox.showerror("Case note", str(exc), parent=self)

    def refresh_notes(self):
        if not self.case:
            return
        chunks = []
        for item in self.case.notes():
            scope = f"run {item['run_id']} / row {item['row_id']}" if item.get("run_id") else "Case note"
            chunks.append(f"{item['utc']}  |  {item['analyst']}  |  {scope}\n\n{item['text']}\n")
        put_text(self.notes_text, "\n------------------------------\n\n".join(chunks) or "No notes yet.")

    def check_audit(self):
        if not self.case_required():
            return
        okay, count, detail = verify_audit(self.case.root / "audit.jsonl")
        messagebox.showinfo("Audit check", f"{'VALID' if okay else 'INVALID'} / {count} events\n\n{detail}\n\n"
                            "This checks internal consistency, not an external digital signature.", parent=self)

    def save_settings(self, quiet=False):
        if not self.idle_required():
            return False
        try:
            self.settings = Settings(self.symbols_var.get(), self.offline_var.get(),
                                     int(self.timeout_var.get()), self.verify_var.get(),
                                     str(user_path(self.export_dir_var.get())), self.auto_export_var.get()).normalized()
            atomic_json(data_root() / "settings.json", asdict(self.settings))
            self.symbols_var.set(self.settings.symbols)
            if not quiet:
                self.status_var.set("Settings saved. Changes apply to the next analysis.")
            return True
        except Exception as exc:
            messagebox.showerror("Settings", str(exc), parent=self)
            return False

    def pick_symbols(self):
        path = filedialog.askdirectory(parent=self, title="Select parent symbol directory")
        if path:
            self.symbols_var.set(path)

    def open_symbols(self):
        if self.save_settings(quiet=True):
            self.open_directory(Path(self.settings.symbols))

    def import_symbol(self):
        if not self.save_settings(quiet=True):
            return
        name = filedialog.askopenfilename(parent=self, title="Import trusted symbol file",
                    filetypes=[("Volatility symbols", "*.json *.json.xz *.json.gz *.zip"), ("All files", "*")])
        if not name:
            return
        source = Path(name)
        family = self.symbol_os.get()
        if source.name.endswith(".zip"):
            if source.name not in ("windows.zip", "linux.zip", "mac.zip"):
                messagebox.showerror("Symbol pack name", "ZIP symbol packs must be named windows.zip, linux.zip, or mac.zip.", parent=self)
                return
            target = Path(self.settings.symbols) / source.name
        elif source.name.endswith((".json", ".json.xz", ".json.gz")):
            target = Path(self.settings.symbols) / family / source.name
        else:
            messagebox.showerror("Symbol file", "Select a JSON, JSON.xz, JSON.gz, or supported ZIP symbol file.", parent=self)
            return
        if target.resolve() == source.resolve():
            self.status_var.set("Symbol file is already in the selected directory.")
            return
        if target.exists() and not messagebox.askyesno("Replace symbol", "Replace the existing symbol file?", parent=self):
            return
        if self.case and target.resolve() == self.case.image.resolve():
            messagebox.showerror("Protected evidence", "The symbol destination cannot overwrite the evidence image.", parent=self)
            return
        def work(cancel, emit):
            import tempfile
            fd, temporary = tempfile.mkstemp(prefix=".symbol-", dir=target.parent)
            try:
                with os.fdopen(fd, "wb") as out, source.open("rb") as inp:
                    while True:
                        if cancel.is_set():
                            raise Cancelled("Symbol import cancelled.")
                        chunk = inp.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            return target
        self.task(work, lambda p: self.status_var.set(f"Imported {p.name}. Volatility will update its cache on the next run."), "Importing symbol file...")

    def open_directory(self, path):
        try:
            if not path.is_dir():
                raise ValueError("Folder does not exist yet.")
            if os.name == "nt":
                os.startfile(str(path))
            else:
                subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            messagebox.showerror("Open folder", str(exc), parent=self)

    def open_case_folder(self):
        if self.case:
            self.open_directory(self.case.root)

    def open_run_folder(self):
        if self.case and self.selected_run:
            self.open_directory(self.case.root / "runs" / self.selected_run)

    def cancel_task(self):
        if self.busy:
            self.cancel_event.set()
            self.status_var.set("Cancellation requested. Stopping the active operation and preserving existing output...")

    def request_close(self):
        if self.busy:
            if not messagebox.askyesno("Operation running", "Cancel the active operation, preserve its output, and close?", parent=self):
                return
            self.closing = True
            self.cancel_task()
        else:
            self._close_now()

    def destroy(self):
        # Cancel scheduled Tcl callbacks before destroying their Python commands.
        try:
            for token in self.tk.call("after", "info"):
                self.after_cancel(token)
        except tk.TclError:
            pass
        super().destroy()

    def _close_now(self):
        if self.case:
            self.case.close()
        self.destroy()


def launch(case_path=None):
    # Explicit paths keep all evidence and configuration outside the source repository.
    data_root().mkdir(parents=True, exist_ok=True, mode=0o700)
    app = App()
    if case_path:
        app.after(300, lambda: app.open_case_path(case_path))
    app.mainloop()
