"""Analyst-controlled binary collection and supplementary event evidence."""
from __future__ import annotations
import json
from pathlib import Path
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
from .theme import MUTED
from .summary import build_summary
from .util import atomic_json
from .engine import run_plugin,plugin_arguments
from .binaries import import_binary,import_hash_intelligence
from .eventlogs import import_event_file


class EvidenceMixin:
    def _evidence_page(self):
        from .gui import frame,label,button,table,readonly_text
        page=self.pages['Evidence lab']
        self.lab_notice=label(page,'Rebuild findings to inspect process paths, collected bytes and timestamp sources.',9,MUTED,anchor='w',wraplength=900,justify='left')
        self.lab_notice.pack(fill='x',pady=(0,8))
        self.lab_tabs=ttk.Notebook(page);self.lab_tabs.pack(fill='both',expand=True)
        procs=frame(self.lab_tabs);files=frame(self.lab_tabs);events=frame(self.lab_tabs)
        self.lab_tabs.add(procs,text='Processes & paths');self.lab_tabs.add(files,text='Files & SHA-256');self.lab_tabs.add(events,text='Timeline & logons')
        tools=frame(procs);tools.pack(fill='x',pady=8)
        button(tools,'Collect selected PE',self.collect_process_pe,True).pack(side='left')
        button(tools,'Rebuild from saved evidence',self.rebuild_findings).pack(side='left',padx=8)
        label(procs,'Windows only: explicit process-image extraction. SHA-256 will describe reconstructed bytes, not the original disk file.',9,MUTED,wraplength=900,justify='left').pack(fill='x',pady=8)
        box,self.process_lab_tree=table(procs,('PID','Process','PPID','Primary path','Byte/hash status'),[65,150,65,360,260],height=10)
        box.pack(fill='both',expand=True);self.process_lab_tree.bind('<Double-1>',self.show_lab_process)
        tools=frame(files);tools.pack(fill='x',pady=8)
        button(tools,'Add acquired file',self.add_acquired_binary,True).pack(side='left')
        button(tools,'Import hash intelligence CSV',self.add_hash_intelligence).pack(side='left',padx=8)
        button(tools,'Copy selected SHA-256',self.copy_binary_hash).pack(side='right')
        label(files,'No sample execution or public upload. PID/path links on acquired files are analyst supplied; representation matters.',9,MUTED,wraplength=900,justify='left').pack(fill='x',pady=8)
        box,self.binary_lab_tree=table(files,('PID','Representation','SHA-256','Validation','Intelligence'),[60,185,460,190,260],height=10)
        box.pack(fill='both',expand=True);self.binary_lab_tree.bind('<Double-1>',self.show_lab_binary)
        tools=frame(events);tools.pack(fill='x',pady=8)
        button(tools,'Import EVTX / XML',self.add_event_log,True).pack(side='left')
        self.timeline_view=tk.StringVar(value='Authentication / session events')
        pick=ttk.Combobox(tools,textvariable=self.timeline_view,state='readonly',width=32,values=['Authentication / session events','Memory-object chronology'])
        pick.pack(side='left',padx=10);pick.bind('<<ComboboxSelected>>',lambda e:self.refresh_lab())
        label(events,'UTC and Philippine time (UTC+08:00) are shown separately. Network creation is not logon time. Imported hosts are never silently merged.',9,MUTED,wraplength=900,justify='left').pack(fill='x',pady=8)
        box,self.event_lab_tree=table(events,('UTC','PHT (UTC+08:00)','Event / object','Host / PID','Account / endpoint'),[220,220,260,160,330],height=10)
        box.pack(fill='both',expand=True);self.event_lab_tree.bind('<Double-1>',self.show_lab_event)
        assessment=frame(self.lab_tabs);self.lab_tabs.add(assessment,text='Analyst assessment')
        from .assessment import DISPOSITIONS
        label(assessment,'Separate your supported conclusion from automated rules. New evidence makes the saved assessment stale.',10,MUTED,wraplength=900,justify='left').pack(fill='x',pady=12)
        self.assessment_disposition=tk.StringVar(value='Unresolved')
        ttk.Combobox(assessment,textvariable=self.assessment_disposition,state='readonly',values=DISPOSITIONS,width=65).pack(anchor='w',pady=8)
        label(assessment,'Reason / scope of conclusion',10).pack(anchor='w',pady=4)
        self.assessment_reason=tk.Text(assessment,height=5,bg='#19191c',fg='#eeeef0',insertbackground='#eeeef0',wrap='word');self.assessment_reason.pack(fill='x')
        label(assessment,'Supporting evidence references (host, run/row, event record, approval/ticket)',10).pack(anchor='w',pady=4)
        self.assessment_refs=tk.Text(assessment,height=3,bg='#19191c',fg='#eeeef0',insertbackground='#eeeef0',wrap='word');self.assessment_refs.pack(fill='x')
        button(assessment,'Record analyst assessment',self.record_assessment,True).pack(anchor='w',pady=12)
        actions=frame(page);actions.pack(fill='x',pady=10)
        button(actions,'Export evidence report',self.report,True).pack(side='right')
        self.lab_processes={};self.lab_binaries={};self.lab_events={}

    def refresh_lab(self):
        if not hasattr(self,'process_lab_tree'):return
        model=self.finding_model
        case_key=str(self.case.root) if self.case else ''
        if case_key!=getattr(self,'_assessment_case_key',None):
            self._assessment_case_key=case_key
            saved=self.case.metadata.get('analyst_assessment',{}) if self.case else {}
            self.assessment_disposition.set(saved.get('disposition','Unresolved'))
            self.assessment_reason.delete('1.0','end');self.assessment_reason.insert('1.0',saved.get('reason',''))
            self.assessment_refs.delete('1.0','end');self.assessment_refs.insert('1.0',saved.get('references',''))
        for tree in (self.process_lab_tree,self.binary_lab_tree,self.event_lab_tree):tree.delete(*tree.get_children())
        self.lab_processes={};self.lab_binaries={};self.lab_events={}
        for i,item in enumerate(model.get('process_inventory',[])):
            key=str(i);self.lab_processes[key]=item
            self.process_lab_tree.insert('','end',iid=key,values=(item['pid'],item['process'],item.get('ppid'),'; '.join(item['paths']),item['hash_status']))
        for i,item in enumerate(model.get('binary_evidence',[])):
            key=str(i);self.lab_binaries[key]=item
            self.binary_lab_tree.insert('','end',iid=key,values=(item.get('pid') or '-',item['representation'],item.get('sha256') or 'Unavailable',item['integrity'],item['reputation']))
        rows=model.get('event_timeline',[]) if self.timeline_view.get().startswith('Authentication') else model.get('memory_timeline',[])
        for i,item in enumerate(rows[:5000]):
            key=str(i);self.lab_events[key]=item
            self.event_lab_tree.insert('','end',iid=key,values=(item.get('time_utc') or item.get('time_status'),item.get('time_pht') or '-',item['kind'],item.get('host') or item.get('pid',''),item.get('account') or item.get('subject','')))
        issues=model.get('binary_issues',[])+model.get('event_issues',[])
        self.lab_notice.configure(text=f"{len(self.lab_processes)} process entries / {len(self.lab_binaries)} binary artifacts / {len(rows)} chronology records. " + ('Integrity/read warnings: '+'; '.join(issues) if issues else 'Double-click any row for original context. Timeline preview limit: 5,000; CSV retains all.'))

    def show_lab_process(self,event=None):
        selected=self.process_lab_tree.selection()
        if selected:self.show_record('Process context',self.lab_processes[selected[0]])
    def show_lab_binary(self,event=None):
        selected=self.binary_lab_tree.selection()
        if selected:self.show_record('Binary evidence and hash provenance',self.lab_binaries[selected[0]])
    def show_lab_event(self,event=None):
        selected=self.event_lab_tree.selection()
        if selected:self.show_record('Timestamp source and interpretation',self.lab_events[selected[0]])
    def copy_binary_hash(self):
        selected=self.binary_lab_tree.selection()
        if not selected:return
        digest=self.lab_binaries[selected[0]].get('sha256')
        if digest:self.clipboard_clear();self.clipboard_append(digest);self.status_var.set('Copied SHA-256 of the selected byte representation.')

    def _supplement_task(self,operation,text):
        case=self.case
        def work(cancel,emit):
            result=operation(case,cancel,emit)
            model=build_summary(case,cancel,emit);atomic_json(case.root/'analysis-summary.json',model)
            return result,model
        def done(value):
            self.refresh_findings(value[1]);self.refresh_case();self.refresh_lab()
            self.show('Evidence lab');self.status_var.set('Evidence imported and findings rebuilt. Export a new report to include the change.')
        self.task(work,done,text)

    def add_acquired_binary(self):
        if not self.case_required():return
        path=filedialog.askopenfilename(parent=self,title='Choose a preserved acquired executable or script (not the memory image)')
        if not path:return
        selected=self.process_lab_tree.selection();proc=self.lab_processes.get(selected[0]) if selected else None
        msg='This copies and hashes the supplied file without running it. The disk file may differ from the captured image. '
        msg+=('It will be linked by your selection to PID '+str(proc['pid'])+'.') if proc else 'No process association is selected.'
        if not messagebox.askokcancel('Acquire and hash bytes',msg,parent=self):return
        self._supplement_task(lambda c,stop,emit:import_binary(c,path,proc['pid'] if proc else None,(proc['paths'] or [''])[0] if proc else '',stop),'Copying and hashing acquired file bytes...')

    def add_hash_intelligence(self):
        if not self.case_required():return
        path=filedialog.askopenfilename(parent=self,title='Supplied hash intelligence: sha256,label,source,reference,representation',filetypes=[('CSV','*.csv'),('All files','*')])
        if path:self._supplement_task(lambda c,stop,emit:import_hash_intelligence(c,path,stop),'Importing source-attributed hash intelligence; no network lookup...')

    def add_event_log(self):
        if not self.case_required():return
        path=filedialog.askopenfilename(parent=self,title='Select acquired EVTX or XML Events export',filetypes=[('Event logs','*.evtx *.xml'),('All files','*')])
        if not path:return
        recovered=messagebox.askyesnocancel('Event-file provenance','Was this file recovered from the memory image?\n\nYes: memory-recovered event file.\nNo: externally collected event log.\nCancel: do not import.\n\nThe app does not automatically carve event logs from RAM.',parent=self)
        if recovered is None:return
        origin='Memory-recovered event file (analyst supplied)' if recovered else 'External event log (analyst supplied)'
        self._supplement_task(lambda c,stop,emit:import_event_file(c,path,origin,stop,emit),'Importing event records with host, provider and time provenance...')

    def collect_process_pe(self):
        if not self.case_required():return
        if self.case.metadata['evidence_os']!='Windows':
            messagebox.showinfo('PE extraction','This action supports Windows PE images. Use an acquired original file for Linux hashes or explicit advanced-plugin extraction.',parent=self);return
        selected=self.process_lab_tree.selection()
        if not selected:messagebox.showinfo('Select a process','Select a process in the inventory first.',parent=self);return
        process=self.lab_processes[selected[0]];pid=process['pid']
        if not pid or 'Ambiguous' in process['identity_status']:
            messagebox.showerror('Identity unresolved','Resolve the process identity before PID-based extraction.',parent=self);return
        plugin=next((p for p in self.catalog.get('plugins',[]) if p['name']=='windows.pslist.PsList'),None)
        if not plugin:messagebox.showerror('Plugin unavailable','Refresh the engine catalog; windows.pslist.PsList is required.',parent=self);return
        if not messagebox.askokcancel('Collect reconstructed executable',f'Extract the primary PE image for PID {pid}?\n\nThe SHA-256 describes reconstructed memory bytes, not necessarily the original on-disk file. Missing pages can limit recovery. No file will be executed.',parent=self):return
        try:args=plugin_arguments(plugin,{'pid':str(pid),'dump':True});settings=self.settings.normalized()
        except Exception as exc:messagebox.showerror('Extraction options',str(exc),parent=self);return
        case=self.case;version=self.catalog['version']
        self.prepare_execution([(plugin,args)])
        def work(cancel,emit):
            result=run_plugin(case,plugin['name'],args,settings,version,cancel,emit)
            if settings.verify_after_batch and not cancel.is_set():case.verify_image(cancel,lambda p:emit('hash_progress',p))
            if cancel.is_set():return result,None
            model=build_summary(case,cancel,emit);atomic_json(case.root/'analysis-summary.json',model);return result,model
        def done(value):
            result,model=value;self.refresh_case()
            if model:self.refresh_findings(model)
            self.show('Evidence lab');self.lab_tabs.select(1)
            self.status_var.set('Extraction '+result['status']+'. Review Files & SHA-256; unavailable/partial outputs are not original-file hashes.')
        self.task(work,done,'Collecting a selected executable image and hashing its bytes...')

    def record_assessment(self):
        if not self.case_required():return
        from .assessment import save_assessment
        try:
            save_assessment(self.case,self.assessment_disposition.get(),self.assessment_reason.get('1.0','end-1c'),self.assessment_refs.get('1.0','end-1c'))
            self.rebuild_findings()
        except Exception as exc:messagebox.showerror('Assessment not recorded',str(exc),parent=self)
