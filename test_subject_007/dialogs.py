"""Path-first import and explicit report-location dialogs."""
from __future__ import annotations
import getpass
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .theme import BG, CARD, TEXT, MUTED, MONO, FONT, VerticalPage
from .paths import common_locations, find_dumps, inspect_image, user_path, workspace_root
from .util import atomic_json, data_root, human_size


def caption(parent, text, size=10, muted=False):
    return tk.Label(parent,text=text,bg=BG,fg=MUTED if muted else TEXT,
                    font=(FONT,size),anchor='w',justify='left')


def copy_text(window,text):
    window.clipboard_clear(); window.clipboard_append(str(text))


def open_local(window,path):
    try:
        path=user_path(path)
        if not path.exists():
            raise ValueError('This saved path no longer exists. Check whether the folder or drive was moved.')
        if os.name=='nt':
            os.startfile(str(path))
        else:
            subprocess.Popen(['xdg-open',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    except Exception as exc:
        messagebox.showerror('Open saved file',str(exc),parent=window)


class ImportDialog(tk.Toplevel):
    def __init__(self,parent,settings,export_directory):
        super().__init__(parent)
        self.result=None
        self.title('Add memory')
        self.configure(bg=BG)
        self.geometry('880x760')
        self.minsize(760,700)
        self.transient(parent); self.grab_set()
        try:
            self.recent=json.loads((data_root()/'recent-locations.json').read_text(encoding='utf-8'))
        except (OSError,ValueError):
            self.recent={}
        scroller=VerticalPage(self); scroller.pack(fill='both',expand=True,padx=24,pady=(20,0))
        body=scroller.body
        self.scroller=scroller
        for event in ('<MouseWheel>','<Button-4>','<Button-5>'):
            self.bind(event,scroller.scroll_event,add='+')
        caption(body,'Start with your memory capture.',20).pack(anchor='w',pady=(0,8))
        caption(body,'Paste a full path, browse, or find likely dump files in common folders.',10,True).pack(anchor='w',pady=(0,14))
        self.variables={key:tk.StringVar(value=value) for key,value in {
            'image':'','name':'','analyst':getpass.getuser(),'os':self.recent.get('os','Windows'),
            'base':self.recent.get('base',str(workspace_root()/'Cases')),
            'exports':export_directory or str(workspace_root()/'Reports')}.items()}
        caption(body,'MEMORY IMAGE / paste full path',9,True).pack(anchor='w',pady=(0,5))
        row=tk.Frame(body,bg=BG); row.pack(fill='x')
        image_entry=ttk.Entry(row,textvariable=self.variables['image']); image_entry.pack(side='left',fill='x',expand=True)
        ttk.Button(row,text='Browse',command=self.browse_image).pack(side='left',padx=(6,0))
        ttk.Button(row,text='Find dumps',command=self.find_images).pack(side='left',padx=(6,0))
        quick=tk.Frame(body,bg=BG); quick.pack(fill='x',pady=(7,12))
        for path in common_locations()[:5]:
            ttk.Button(quick,text=path.name,command=lambda p=path: self.browse_image(p)).pack(side='left',padx=(0,5))
        for key,title in [('name','CASE NAME / blank uses the filename'),('analyst','ANALYST'),
                          ('os','CAPTURED OPERATING SYSTEM / not this workstation'),
                          ('base','CASE STORAGE / image, logs and evidence records are kept separate'),
                          ('exports','REPORT DESTINATION / paste the folder where exports should be saved')]:
            caption(body,title,8,True).pack(anchor='w',pady=(8,4))
            row=tk.Frame(body,bg=BG); row.pack(fill='x')
            if key=='os':
                ttk.Combobox(row,textvariable=self.variables[key],values=['Windows','Linux','macOS','Unknown'],state='readonly').pack(fill='x')
            else:
                ttk.Entry(row,textvariable=self.variables[key]).pack(side='left',fill='x',expand=True)
                if key in ('base','exports'):
                    ttk.Button(row,text='Browse',command=lambda k=key:self.browse_directory(k)).pack(side='left',padx=(6,0))
        self.online=tk.BooleanVar(value=not settings.offline)
        self.auto_export=tk.BooleanVar(value=settings.auto_export)
        ttk.Checkbutton(body,text='Allow approved symbol downloads (uses network; the memory image is not uploaded)',variable=self.online).pack(anchor='w',pady=(14,3))
        ttk.Checkbutton(body,text='Automatically save PDF, HTML and CSV reports after analysis',variable=self.auto_export).pack(anchor='w',pady=(0,7))
        note=caption(body,'After hashing, choose an investigation goal. Linux needs matching kernel symbols.\nThe file is referenced in place. A readable file is not a guarantee of a supported capture.',9,True)
        note.configure(wraplength=810); note.pack(anchor='w',pady=(2,10))
        actions=tk.Frame(self,bg=BG); actions.pack(side='bottom',fill='x',padx=24,pady=16,before=scroller)
        self.accept_button=ttk.Button(actions,text='Add memory & continue',command=self.accept,style='Accent.TButton')
        self.accept_button.pack(side='right')
        ttk.Button(actions,text='Cancel',command=self.destroy).pack(side='right',padx=8)
        image_entry.focus_set()

    def browse_image(self,initial=None):
        folder=initial or Path(self.recent.get('image_directory',str(Path.home()/'Downloads')))
        if not Path(folder).is_dir():
            folder=Path.home()
        path=filedialog.askopenfilename(parent=self,title='Select an acquired system-memory image',initialdir=str(folder),
                                        filetypes=[('All files','*'),('Common memory captures','*.raw *.mem *.dmp *.dump *.vmem *.lime *.bin *.elf')])
        if path:
            self.choose_image(path)

    def choose_image(self,path):
        self.variables['image'].set(path)
        if not self.variables['name'].get().strip():
            self.variables['name'].set(Path(path).stem)

    def find_images(self):
        finder=FindDumpDialog(self)
        self.wait_window(finder)
        if finder.result:
            self.choose_image(finder.result)
        self.grab_set()

    def browse_directory(self,key):
        path=filedialog.askdirectory(parent=self,title='Choose '+('case storage' if key=='base' else 'report destination'),mustexist=False,
                                     initialdir=str(Path.home()))
        if path:
            self.variables[key].set(path)

    def accept(self):
        try:
            values={k:v.get().strip() for k,v in self.variables.items()}
            path=user_path(values['image'])
            inspect_image(path)
            values['image']=str(path)
            values['base']=str(user_path(values['base']))
            values['exports']=str(user_path(values['exports']))
            values['name']=values['name'] or path.stem
            if not values['analyst']:
                raise ValueError('Enter an analyst name.')
            if Path(values['base'])==path or Path(values['exports'])==path:
                raise ValueError('Case storage and export destinations must be folders, not the evidence file.')
            Path(values['base']).mkdir(parents=True,exist_ok=True)
            Path(values['exports']).mkdir(parents=True,exist_ok=True)
            atomic_json(data_root()/'recent-locations.json',{'image_directory':str(path.parent),'base':values['base'],'os':values['os']})
            self.result={**values,'online':self.online.get(),'auto_export':self.auto_export.get()}
            self.destroy()
        except Exception as exc:
            messagebox.showerror('Check the memory image / paths',str(exc),parent=self)


class FindDumpDialog(tk.Toplevel):
    def __init__(self,parent):
        super().__init__(parent)
        self.result=None; self.cancel=threading.Event(); self.events=queue.Queue(); self.running=False
        self.title('Find memory dump candidates'); self.geometry('970x520'); self.configure(bg=BG)
        self.transient(parent); self.grab_set(); self.protocol('WM_DELETE_WINDOW',self.close)
        body=tk.Frame(self,bg=BG);body.pack(fill='both',expand=True,padx=20,pady=18)
        caption(body,'Find likely memory captures',18).pack(anchor='w')
        caption(body,'Searches filenames only, skips hidden folders/symlinks, and limits depth and entries. Candidates are not validated captures.',9,True).pack(anchor='w',pady=8)
        row=tk.Frame(body,bg=BG);row.pack(fill='x',pady=8)
        self.root_var=tk.StringVar()
        ttk.Entry(row,textvariable=self.root_var).pack(side='left',fill='x',expand=True)
        ttk.Button(row,text='Choose folder',command=self.choose_root).pack(side='left',padx=6)
        self.search_button=ttk.Button(row,text='Search',command=self.search);self.search_button.pack(side='left')
        self.common_button=ttk.Button(row,text='Common folders',command=lambda:self.search(common=True));self.common_button.pack(side='left',padx=(6,0))
        self.status=tk.StringVar(value='Choose a folder, or search Downloads, Desktop, Documents and common mount locations.')
        caption(body,'',9,True).pack_forget()
        tk.Label(body,textvariable=self.status,bg=BG,fg=MUTED,anchor='w',wraplength=900).pack(fill='x',pady=8)
        holder=tk.Frame(body,bg=BG);holder.pack(fill='both',expand=True)
        self.tree=ttk.Treeview(holder,columns=('path','size'),show='headings',selectmode='browse')
        self.tree.heading('path',text='Candidate path');self.tree.column('path',width=730)
        self.tree.heading('size',text='Size');self.tree.column('size',width=100,stretch=False)
        scroll=ttk.Scrollbar(holder,orient='vertical',command=self.tree.yview);self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y');self.tree.pack(fill='both',expand=True)
        self.tree.bind('<Double-1>',lambda _:self.accept())
        row=tk.Frame(body,bg=BG);row.pack(fill='x',pady=(12,0))
        ttk.Button(row,text='Use selected file',command=self.accept,style='Accent.TButton').pack(side='right')
        ttk.Button(row,text='Close',command=self.close).pack(side='right',padx=8)
        self.poll_token=self.after(100,self.poll)

    def choose_root(self):
        path=filedialog.askdirectory(parent=self,title='Choose a folder or mounted evidence drive')
        if path:self.root_var.set(path)

    def search(self,common=False):
        if self.running:return
        try:
            roots=common_locations() if common else [user_path(self.root_var.get())]
            if not roots or any(not p.is_dir() for p in roots):
                raise ValueError('Choose an existing folder to search.')
        except Exception as exc:
            messagebox.showerror('Search folder',str(exc),parent=self);return
        self.cancel.clear();self.running=True
        self.search_button.configure(state='disabled');self.common_button.configure(state='disabled')
        self.tree.delete(*self.tree.get_children());self.status.set('Searching filenames only...')
        def work():
            try:self.events.put((find_dumps(roots,self.cancel),None))
            except Exception as exc:self.events.put((None,str(exc)))
        threading.Thread(target=work,daemon=True,name='ts007-find-dumps').start()

    def poll(self):
        try:
            value,error=self.events.get_nowait();self.running=False
            self.search_button.configure(state='normal');self.common_button.configure(state='normal')
            if error:self.status.set(error)
            else:
                records,limited=value
                for i,r in enumerate(records):self.tree.insert('','end',iid=str(i),values=(r['path'],human_size(r['size'])))
                self.status.set(f'{len(records)} candidate files. '+('Scan limit reached; narrow the search folder.' if limited else 'Select a file, then verify it at import.'))
        except queue.Empty:pass
        self.poll_token=self.after(100,self.poll)

    def accept(self):
        selection=self.tree.selection()
        if selection:
            self.result=self.tree.item(selection[0],'values')[0]
            self.close()

    def close(self):
        self.cancel.set()
        if getattr(self,'poll_token',None):self.after_cancel(self.poll_token)
        self.destroy()


class ExportDialog(tk.Toplevel):
    def __init__(self,parent,paths):
        super().__init__(parent)
        self.title('Reports saved');self.geometry('980x640');self.minsize(800,500);self.configure(bg=BG)
        self.transient(parent)
        body=tk.Frame(self,bg=BG);body.pack(fill='both',expand=True,padx=24,pady=22)
        caption(body,'Your exports are saved here.',20).pack(anchor='w',pady=(0,10))
        caption(body,'Each path is selectable. Copy it into your file manager, or open the file directly.',10,True).pack(anchor='w',pady=(0,16))
        scroll=VerticalPage(body);scroll.pack(fill='both',expand=True)
        self.path_scroll=scroll
        for event in ('<MouseWheel>','<Button-4>','<Button-5>'):
            self.bind(event,scroll.scroll_event,add='+')
        self.path_vars=[]
        for name,path in paths.items():
            row=tk.Frame(scroll.body,bg=BG);row.pack(fill='x',pady=4)
            lab=caption(row,name.upper(),9,True);lab.configure(width=13);lab.pack(side='left')
            var=tk.StringVar(value=path);self.path_vars.append(var)
            ttk.Entry(row,textvariable=var,state='readonly').pack(side='left',fill='x',expand=True)
            ttk.Button(row,text='Copy',command=lambda p=path:copy_text(self,p)).pack(side='left',padx=6)
            ttk.Button(row,text='Open',command=lambda p=path:open_local(self,p)).pack(side='left')
        row=tk.Frame(body,bg=BG);row.pack(side='bottom',fill='x',pady=(14,0),before=scroll)
        self.action_footer=row
        folder=str(Path(next(iter(paths.values()))).parent)
        ttk.Button(row,text='Open report folder',command=lambda:open_local(self,folder)).pack(side='left')
        ttk.Button(row,text='Copy folder path',command=lambda:copy_text(self,folder)).pack(side='left',padx=8)
        ttk.Button(row,text='Done',command=self.destroy,style='Accent.TButton').pack(side='right')
