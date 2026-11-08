"""Investigation planning, live execution and evidence-linked findings views."""
from __future__ import annotations
from collections import deque
from datetime import datetime, timezone
import json
import tkinter as tk
from tkinter import ttk, messagebox
from .profiles import DESCRIPTIONS, COMPLETE, COMPLETE_LIMITS, resolve, default_jobs
from .planning import build_plan
from .engine import plugin_arguments
from .summary import build_summary
from .util import atomic_json
from .theme import BG, CARD, INPUT, BORDER, TEXT, MUTED, RED, GOOD, FONT, MONO


class InvestigationMixin:
    def init_investigation_state(self):
        self.checked_plugins = set()
        self.saved_plugin_values = {}
        self.profile_missing = []
        self.live_blocks = deque(maxlen=180)
        self.live_chars = 0
        self.execution_plan = []
        self.execution_active = None
        self.execution_done = 0
        self.finding_model = {}
        self.finding_rows = {}
        self._options_dirty = False
        self.profile_applied = None
        self.last_plan = None

    def planner_header(self, parent):
        from .gui import frame, label, button
        bar = frame(parent, CARD)
        label(bar, 'INVESTIGATION', 8, MUTED, bg=CARD, font=(MONO, 8)).grid(row=0,column=0,sticky='w',padx=14,pady=(10,3))
        self.profile_var = tk.StringVar(value='Quick triage')
        pick = ttk.Combobox(bar, textvariable=self.profile_var, values=list(DESCRIPTIONS), state='readonly', width=32)
        pick.grid(row=1,column=0,sticky='w',padx=14,pady=(0,10))
        button(bar, 'Apply preset', self.apply_profile).grid(row=1,column=1,padx=(0,12),pady=(0,10))
        self.selection_label = label(bar, '0 plugins selected', 10, TEXT, bg=CARD)
        self.selection_label.grid(row=0,column=2,sticky='w',padx=10)
        self.terms_var = tk.StringVar()
        self.term_entry = ttk.Entry(bar, textvariable=self.terms_var)
        self.term_entry.grid(row=1,column=2,sticky='ew',padx=10,pady=(0,10))
        label(bar, 'Optional terms, comma-separated', 8, MUTED, bg=CARD,anchor='w',wraplength=210).grid(row=2,column=2,sticky='w',padx=10,pady=(0,10))
        button(bar,'Start checked plugins',self.run_checked,True).grid(row=1,column=3,padx=14,pady=(0,10))
        bar.columnconfigure(2,weight=1)
        self.profile_description = label(bar,DESCRIPTIONS[self.profile_var.get()],9,MUTED,bg=CARD,justify='left',anchor='w',wraplength=900)
        self.profile_description.grid(row=3,column=0,columnspan=4,sticky='ew',padx=14,pady=(0,12))
        self.profile_description.bind('<Configure>',lambda e:self.profile_description.configure(wraplength=max(300,e.width)))
        pick.bind('<<ComboboxSelected>>', self.profile_changed)
        return bar

    def checkbox_images(self):
        self.unchecked_image = tk.PhotoImage(width=16,height=16)
        self.checked_image = tk.PhotoImage(width=16,height=16)
        for img in (self.unchecked_image,self.checked_image):
            img.put(INPUT,to=(0,0,16,16))
            for rect in ((1,1,15,2),(1,14,15,15),(1,1,2,15),(14,1,15,15)):
                img.put(MUTED,to=rect)
        self.checked_image.put(TEXT,to=(1,1,15,15))
        for x,y in ((4,7),(5,8),(6,9),(7,8),(8,7),(9,6),(10,5),(11,4)):
            self.checked_image.put(BG,to=(x,y,x+2,y+2))

    def toggle_plugin_event(self,event):
        if self.plugin_tree.identify_column(event.x) != '#0':
            return
        row = self.plugin_tree.identify_row(event.y)
        if row:
            self.plugin_tree.selection_set(row)
            self.toggle_plugin(row)
            return 'break'

    def toggle_selected_plugin(self,event=None):
        rows = self.plugin_tree.selection()
        if rows:
            self.toggle_plugin(rows[0])
        return 'break'

    def toggle_plugin(self,name):
        if self.busy:
            return
        self.profile_var.set('Custom'); self.profile_applied='Custom'; self.profile_missing=[]
        if name in self.checked_plugins:
            self.checked_plugins.remove(name)
        else:
            self.checked_plugins.add(name)
        if self.plugin_tree.exists(name):
            self.plugin_tree.item(name,image=self.checked_image if name in self.checked_plugins else self.unchecked_image)
        self.update_selection_count()

    def select_shown(self):
        if not self.busy:
            self.profile_var.set('Custom'); self.profile_applied='Custom'; self.profile_missing=[]
            self.checked_plugins.update(self.plugin_tree.get_children())
            self.filter_plugins()
            self.update_selection_count()

    def clear_checked(self):
        if not self.busy:
            self.profile_var.set('Custom'); self.profile_applied='Custom'; self.profile_missing=[]
            self.checked_plugins.clear()
            self.filter_plugins()
            self.update_selection_count()

    def profile_changed(self, event=None):
        profile = self.profile_var.get()
        self.profile_description.configure(text=DESCRIPTIONS[profile])
        if profile == 'Custom':
            # Switching to Custom must not wipe checked plugins or saved options.
            self.profile_applied = 'Custom'
            self.profile_missing = []
            self.update_selection_count()
        else:
            self.status_var.set('Click Apply preset to replace the checked selection with ' + profile + '.')

    def capture_plugin_options(self):
        if self.current_plugin and self._options_dirty:
            # Preserve explicit clearing/False, not just truthy option edits.
            self.saved_plugin_values[self.current_plugin['name']] = {k: v.get() for k, v in self.option_vars.items()}
            self._options_dirty = False

    def mark_plugin_options_dirty(self, *args):
        self._options_dirty = True

    def make_plan(self):
        self.capture_plugin_options()
        system = self.case.metadata['evidence_os'] if self.case else self.plugin_family.get()
        plan = build_plan(self.catalog, self.checked_plugins, self.saved_plugin_values,
                          self.profile_var.get(), system, self.profile_missing)
        if self.profile_var.get() == COMPLETE:
            plan.notices.insert(0, COMPLETE_LIMITS)
        self.last_plan = plan
        return plan

    def update_selection_count(self):
        # Validation is deliberately performed on demand, not on every keystroke.
        self.selection_label.configure(text=f'{len(self.checked_plugins)} plugins checked' +
            (f' / {len(self.profile_missing)} unavailable' if self.profile_missing else ''))
        self.last_plan = None
        if hasattr(self,"refresh_guided"):
            self.refresh_guided()

    def review_plan(self, plan):
        from .preflight_ui import PlanReview
        dialog = PlanReview(self, plan)
        self.wait_window(dialog)
        return dialog.result

    def configure_planned_plugin(self, name):
        if hasattr(self,"open_advanced"):
            self.open_advanced()
        self.plugin_search.set('')
        self.plugin_family.set('All')
        self.filter_plugins()
        if self.plugin_tree.exists(name):
            self.plugin_tree.selection_set(name)
            self.plugin_tree.see(name)
            self.select_plugin()
            self.status_var.set('Configure ' + name + ', save options, then start checked plugins again.')

    def review_checked(self):
        if self.busy:
            return
        self._start_checked(force_review=True)

    def apply_profile(self,quiet=False):
        if self.busy:
            return
        if self.profile_var.get() == 'Custom':
            self.profile_changed()
            self.status_var.set('Custom plan retained. Check plugins and review inputs before starting.')
            return
        system = self.case.metadata['evidence_os'] if self.case else self.plugin_family.get()
        if system not in ('Windows','Linux','macOS'):
            system = 'Windows'
        selected, missing = resolve(self.catalog,system,self.profile_var.get())
        self.checked_plugins = {p['name'] for p in selected}
        self.saved_plugin_values = {}
        self.current_plugin = None
        self.option_vars = {}
        self.profile_missing = missing
        self.profile_applied = self.profile_var.get()
        self._options_dirty = False
        self.plugin_family.set(system)
        self.filter_plugins()
        self.update_selection_count()
        description = DESCRIPTIONS[self.profile_var.get()]
        if missing:
            description += '\nUnavailable in this engine: ' + ', '.join(missing)
        self.profile_description.configure(text=description)
        if selected:
            name = selected[0]['name']
            if self.plugin_tree.exists(name):
                self.plugin_tree.selection_set(name)
                self.select_plugin()
        if not selected and not quiet and not missing:
            self.status_var.set('Custom plan: check the plugins you need.')

    def save_plugin_options(self):
        if self.busy:return
        if self.current_plugin:
            values = {k:v.get() for k,v in self.option_vars.items()}
            try:
                plugin_arguments(self.current_plugin,values)
            except Exception as exc:
                messagebox.showerror('Plugin options',str(exc),parent=self)
                return
            self.saved_plugin_values[self.current_plugin['name']] = values
            self._options_dirty = False
            self.status_var.set('Options saved for ' + self.current_plugin['name'])

    def run_checked(self):
        self._start_checked()

    def _start_checked(self, force_review=False):
        if not self.case_required():
            return
        if not self.checked_plugins:
            messagebox.showinfo('No plugins selected', 'Apply a preset or check individual plugins.', parent=self)
            return
        if self.profile_var.get() != 'Custom' and self.profile_applied != self.profile_var.get():
            messagebox.showinfo('Apply the preset first', 'Click Apply preset before starting this preset, or choose Custom to keep your current selection.', parent=self)
            return
        try:
            plan = self.make_plan()
            if force_review or plan.deferred or plan.missing or plan.notices:
                decision = self.review_plan(plan)
                if not decision:
                    return
                if decision[0] == 'configure':
                    self.configure_planned_plugin(decision[1])
                    return
                if decision[0] != 'run':
                    return
            if not plan.items:
                messagebox.showinfo('No ready tasks', 'All selected tasks need configuration. No analysis was started.', parent=self)
                return
            # Only approved plans are recorded. Cancel/Edit does not change a case.
            from .profiles import goal_details
            self.case.metadata["investigation_goal"] = goal_details(self.profile_var.get())
            self.case.metadata.update(investigation_profile=self.profile_var.get(), profile_missing=self.profile_missing,
                                      investigation_terms=[t.strip() for t in self.terms_var.get().split(',') if t.strip()])
            self.run_batch(plan.items, triage=True, preflight=plan.record())
        except Exception as exc:
            messagebox.showerror('Investigation plan', str(exc), parent=self)

    def _execution_page(self):
        from .gui import frame,label,button,table
        page=self.pages['Execution']
        head=frame(page,CARD);head.pack(fill='x',pady=(0,12))
        self.execution_title=tk.StringVar(value='No analysis in progress')
        self.execution_time=tk.StringVar(value='00:00')
        self.execution_size=tk.StringVar(value='0 bytes')
        for col,(title,var) in enumerate([('CURRENT OPERATION',self.execution_title),('ELAPSED',self.execution_time),('OUTPUT WRITTEN',self.execution_size)]):
            box=frame(head,CARD);box.grid(row=0,column=col,sticky='nsew',padx=16,pady=12)
            label(box,title,8,MUTED,bg=CARD,font=(MONO,8)).pack(anchor='w')
            lb=label(box,textvariable=var,size=12,bold=True,bg=CARD,anchor='w',justify='left',wraplength=540)
            lb.pack(fill='x',anchor='w',pady=(6,0))
            box.bind('<Configure>',lambda e,w=lb:w.configure(wraplength=max(120,e.width)))
            if col==0:self.live_operation_label=lb
        head.columnconfigure(0,weight=1)
        self.phase_var=tk.StringVar(value='Start an investigation from Analyze. Raw output stays in the case run folder.')
        label(page,textvariable=self.phase_var,color=MUTED,size=9,anchor='w').pack(fill='x',pady=(0,6))
        self.phase_progress=ttk.Progressbar(page,mode='indeterminate');self.phase_progress.pack(fill='x',pady=(0,10))
        box,self.execution_tree=table(page,('Plugin / task','State','Rows','Time'),[520,140,70,80],height=3)
        box.pack(fill='x',pady=(0,10))
        controls=frame(page);controls.pack(fill='x',pady=(0,8))
        self.log_source=tk.StringVar(value='All output')
        choice=ttk.Combobox(controls,textvariable=self.log_source,values=['All output','Progress / stderr','Result CSV','Engine detail'],state='readonly',width=20)
        choice.pack(side='left');choice.bind('<<ComboboxSelected>>',lambda e:self.render_live())
        self.follow_log=tk.BooleanVar(value=True);self.pause_log=tk.BooleanVar(value=False)
        ttk.Checkbutton(controls,text='Follow output',variable=self.follow_log).pack(side='left',padx=12)
        ttk.Checkbutton(controls,text='Pause view',variable=self.pause_log,command=self.render_live).pack(side='left')
        button(controls,'Copy visible log',lambda:self.copy_value(self.live_text.get('1.0','end'))).pack(side='right')
        button(controls,'Open run folder',self.open_run_folder).pack(side='right',padx=8)
        area=frame(page);area.pack(fill='both',expand=True)
        self.live_text=tk.Text(area,bg=INPUT,fg=TEXT,font=(MONO,9),wrap='none',state='disabled',relief='flat',padx=12,pady=12,
                               highlightbackground=BORDER,highlightthickness=1,insertbackground=TEXT)
        v=ttk.Scrollbar(area,orient='vertical',command=self.live_text.yview)
        h=ttk.Scrollbar(area,orient='horizontal',command=self.live_text.xview)
        self.live_text.configure(yscrollcommand=v.set,xscrollcommand=h.set)
        self.live_text.grid(row=0,column=0,sticky='nsew');v.grid(row=0,column=1,sticky='ns');h.grid(row=1,column=0,sticky='ew')
        area.columnconfigure(0,weight=1);area.rowconfigure(0,weight=1)
        for tag,color in [('stderr',TEXT),('stdout',MUTED),('engine','#92929b'),('app',RED)]:
            self.live_text.tag_configure(tag,foreground=color)
        label(page,'Live view is bounded for responsiveness. Complete unmodified stdout, stderr and engine logs are retained on disk.',8,MUTED).pack(anchor='w',pady=(7,0))

    def prepare_execution(self,items,preflight=None):
        self.live_blocks.clear();self.live_chars=0;self.execution_tree.delete(*self.execution_tree.get_children())
        self.execution_plan=[];self.execution_done=0;self.execution_active=None
        for i,(p,args) in enumerate(items):
            key='plan-'+str(i);self.execution_plan.append(key)
            text=p['name']+('  '+' '.join(args) if args else '')
            self.execution_tree.insert('', 'end',iid=key,values=(text,'Queued','-', '-'))
        self.append_live({'source':'app','text':f'Plan: {len(items)} plugin tasks. Files are preserved; findings require analyst review.\n'})
        for issue in (preflight or {}).get('deferred', []):
            self.execution_tree.insert('', 'end', values=(issue['plugin'], 'Not run / input', '-', '-'))
            self.append_live({'source':'app','text':'NOT RUN: ' + issue['plugin'] + ' / ' + issue['reason'] + '\n'})
        for name in (preflight or {}).get('unavailable', []):
            self.execution_tree.insert('', 'end', values=(name, 'Unavailable', '-', '-'))
        self.show('Execution')

    def append_live(self,payload):
        source,text=payload['source'],payload['text']
        text=''.join(c for c in text if c in '\n\t' or ord(c)>=32)
        # Keep recent data for filter changes; each block has a receipt timestamp, not an artifact timestamp.
        stamp=datetime.now(timezone.utc).strftime('%H:%M:%S')
        block=f'[{stamp} UTC / {source}] '+text.rstrip('\n')+'\n'
        self.live_blocks.append((source,block))
        if not self.pause_log.get() and self.source_visible(source):
            self.live_text.configure(state='normal')
            self.live_text.insert('end',block,source)
            if int(self.live_text.index('end-1c').split('.')[0])>2500:
                self.live_text.delete('1.0','end-2000l')
            if int(self.live_text.count('1.0','end','chars')[0])>500000:
                self.live_text.delete('1.0','end-350000c')
            self.live_text.configure(state='disabled')
            if self.follow_log.get():
                self.live_text.see('end')

    def source_visible(self,source):
        return source=='app' or self.log_source.get()=='All output' or {'Progress / stderr':'stderr','Result CSV':'stdout','Engine detail':'engine'}.get(self.log_source.get())==source

    def render_live(self):
        if self.pause_log.get():
            return
        self.live_text.configure(state='normal');self.live_text.delete('1.0','end')
        for source,text in self.live_blocks:
            if self.source_visible(source):
                self.live_text.insert('end',text,source)
        if int(self.live_text.count('1.0','end','chars')[0])>500000:
            self.live_text.delete('1.0','end-350000c')
        self.live_text.configure(state='disabled')
        if self.follow_log.get():self.live_text.see('end')

    def live_started(self,run):
        self.execution_title.set(run['plugin'])
        self.execution_active=self.execution_plan[self.execution_done] if self.execution_done<len(self.execution_plan) else None
        self.phase_progress.configure(mode='indeterminate');self.phase_progress.start(15)
        self.append_live({'source':'app','text':'Started '+run['plugin']+'\nArguments: '+repr(run['command_argv'])+'\n'})
        if self.execution_active:
            values=list(self.execution_tree.item(self.execution_active,'values'));values[1]='Running'
            self.execution_tree.item(self.execution_active,values=values);self.execution_tree.see(self.execution_active)

    def live_progress(self,event):
        from .util import human_size
        elapsed=int(event.get('elapsed',0));self.execution_time.set(f'{elapsed//60:02d}:{elapsed%60:02d}')
        self.execution_size.set(human_size(event.get('bytes_written',0)))
        phase=event.get('phase','Engine working');pct=event.get('percent')
        quiet=event.get('quiet_seconds',0)
        suffix=f' / no new output for {quiet:.0f}s; process is still running' if quiet>=5 else ''
        self.phase_var.set((f'Engine stage: {pct:.1f}% / ' if pct is not None else '')+phase+suffix)
        if pct is not None:
            self.phase_progress.stop();self.phase_progress.configure(mode='determinate',value=pct)
        if self.execution_active:
            values=list(self.execution_tree.item(self.execution_active,'values'));values[3]=f'{elapsed}s'
            self.execution_tree.item(self.execution_active,values=values)

    def live_finished(self,run):
        self.phase_progress.stop()
        if self.execution_active:
            values=list(self.execution_tree.item(self.execution_active,'values'))
            values[1:]=[run['status'],run.get('rows',0),str(run.get('elapsed_seconds',0))+'s']
            self.execution_tree.item(self.execution_active,values=values)
        self.execution_done+=1
        self.append_live({'source':'app','text':f"Finished {run['plugin']}: {run['status']} / {run.get('rows',0)} indexed rows\n"})
        self.phase_var.set(f'{self.execution_done} of {len(self.execution_plan)} tasks finished. Post-processing may still be running.')

    def _findings_page(self):
        from .gui import frame,label,button,table,readonly_text
        page=self.pages['Findings'];tools=frame(page);tools.pack(fill='x',pady=(0,10))
        self.finding_search=tk.StringVar();self.finding_priority=tk.StringVar(value='All priorities')
        self.finding_category=tk.StringVar(value='All categories')
        self.category_picker=ttk.Combobox(tools,textvariable=self.finding_category,state='readonly',width=19,values=['All categories'])
        self.category_picker.pack(side='left',padx=(0,8))
        self.category_picker.bind('<<ComboboxSelected>>',lambda e:self.filter_findings())
        ttk.Entry(tools,textvariable=self.finding_search).pack(side='left',fill='x',expand=True)
        pick=ttk.Combobox(tools,textvariable=self.finding_priority,values=['All priorities','High','Medium','Review','Informational'],state='readonly',width=18)
        pick.pack(side='left',padx=10)
        button(tools,'Rebuild findings',self.rebuild_findings).pack(side='right')
        self.finding_search.trace_add('write',lambda *_:self.filter_findings());pick.bind('<<ComboboxSelected>>',lambda e:self.filter_findings())
        self.show_context_var=tk.BooleanVar(value=False)
        ttk.Checkbutton(page,text='Include background context (remote tooling and conventional ports)',variable=self.show_context_var,command=self.filter_findings).pack(anchor='w',pady=(0,6))
        self.finding_notice=label(page,'No analysis reviewed. Import a capture and choose an investigation.',9,MUTED,anchor='w')
        self.finding_notice.pack(fill='x',pady=(0,10))
        pane=ttk.Panedwindow(page,orient='vertical');pane.pack(fill='both',expand=True)
        box,self.finding_tree=table(pane,('ID','Priority','Category','PID','Specific review item'),[70,90,155,65,550],height=8)
        pane.add(box,weight=1)
        detail=frame(pane);pane.add(detail,weight=1)
        self.finding_detail=readonly_text(detail,9);self.finding_detail.pack(fill='both',expand=True)
        self.finding_tree.bind('<<TreeviewSelect>>',self.show_finding)
        actions=frame(page);actions.pack(fill='x',pady=(10,0))
        button(actions,'Open first evidence row',self.open_finding_source).pack(side='left')
        button(actions,'Export PDF / HTML / CSV',self.report,True).pack(side='right')

    def refresh_findings(self,model=None):
        if model is None and self.case:
            path=self.case.root/'analysis-summary.json'
            if path.exists():
                try:model=json.loads(path.read_text(encoding='utf-8'))
                except (ValueError,OSError):model={}
        # Older cached summaries used broad string-match rules. Preserve the file,
        # but do not redisplay those findings as the current assessment.
        stale=bool(model and model.get('analysis_logic')!='evidence-led' and 'actionable_count' not in model)
        self.finding_model={} if stale else (model or {})
        if hasattr(self,'category_picker'):
            cats=['All categories']+sorted({x['category'] for x in self.finding_model.get('findings',[])})
            self.category_picker.configure(values=cats)
            if self.finding_category.get() not in cats:self.finding_category.set('All categories')
        self.filter_findings()
        if hasattr(self,'refresh_lab'):self.refresh_lab()
        if stale:
            self.finding_notice.configure(text='Saved summary uses earlier review rules. Click Rebuild findings; original plugin evidence is preserved.')

    def filter_findings(self):
        if not hasattr(self,'finding_tree'):return
        self.finding_tree.delete(*self.finding_tree.get_children());self.finding_rows={}
        term=self.finding_search.get().casefold();priority=self.finding_priority.get()
        all_rows=self.finding_model.get('findings',[])
        for item in all_rows:
            if item.get('layer')=='Context' and not self.show_context_var.get():continue
            if self.finding_category.get()!='All categories' and item['category']!=self.finding_category.get():continue
            if priority!='All priorities' and item['priority']!=priority:continue
            if term and term not in json.dumps(item,ensure_ascii=False).casefold():continue
            key=item['id'];self.finding_rows[key]=item
            self.finding_tree.insert('', 'end',iid=key,values=(key,item['priority'],item['category'],item.get('pid') or '-',item['title']))
        flags=len(self.finding_model.get('quality_flags',[]))
        self.finding_notice.configure(text=f'{len(self.finding_rows)} shown / {self.finding_model.get("actionable_count",len(all_rows))} actionable / {self.finding_model.get("context_count",0)} context / {flags} quality rows. No automatic infection verdict.')

    def show_finding(self,event=None):
        from .gui import put_text
        selected=self.finding_tree.selection()
        if not selected:return
        item=self.finding_rows[selected[0]]
        parts=[item['id']+' / '+item['title'],item['priority']+' priority / '+item['status'],
               '\nOBSERVATION\n'+item['observation'],'\nCONTEXT\n'+item['context'],
               '\nASSESSMENT\n'+item['interpretation'],'\nNEXT ACTION\n'+item['action'],
               '\nEVIDENCE REFERENCES\n'+'\n'.join(f"{r['plugin']} / {r['run_id']} / row {r['row_id']}" for r in item['references'])]
        put_text(self.finding_detail,'\n'.join(parts))

    def open_finding_source(self):
        selected=self.finding_tree.selection()
        if not selected:return
        refs=self.finding_rows[selected[0]].get('references',[])
        if not refs:return
        ref=refs[0]
        if ref['plugin'].startswith('supplement.') or not ref.get('row_id'):
            self.show('Evidence lab');return
        self.selected_run=ref['run_id'];self.result_filter.set('');self.page_number=(ref['row_id']-1)//200
        self.show('Results');self.refresh_runs();self.load_result()
        if self.result_tree.exists(str(ref['row_id'])):
            self.result_tree.selection_set(str(ref['row_id']));self.result_tree.see(str(ref['row_id']))

    def rebuild_findings(self):
        if not self.case_required():return
        case=self.case
        def work(cancel,emit):
            model=build_summary(case,cancel,emit);atomic_json(case.root/'analysis-summary.json',model);return model
        self.task(work,self.refresh_findings,'Reviewing existing evidence; memory analysis is not being rerun...')
