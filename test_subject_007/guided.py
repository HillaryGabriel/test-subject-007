"""Goal-first desktop controls. Advanced plugin options are a separate tab.

Selection applies a curated plan but never starts a subprocess. All execution uses
existing option preflight, immutable original output, and per-case job recording.
"""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk
from .profiles import GOALS, goal_details, DESCRIPTIONS, resolve
from .theme import BG, CARD, INPUT, BORDER, TEXT, MUTED, RED, FONT, MONO, VerticalPage
from .util import human_size


class GoalCard(tk.Canvas):
    def __init__(self, parent, goal, choose):
        super().__init__(parent, height=104, bg=BG, highlightthickness=0,
                         takefocus=True, cursor='hand2', bd=0)
        self.goal, self.choose, self.selected = goal, choose, False
        self.bind('<Configure>', lambda _: self.draw())
        self.bind('<Button-1>', lambda _: choose(goal['profile']))
        self.bind('<Return>', lambda _: choose(goal['profile']))
        self.bind('<space>', lambda _: choose(goal['profile']))
        self.bind('<FocusIn>', lambda _: self.draw())
        self.bind('<FocusOut>', lambda _: self.draw())

    def draw(self):
        self.delete('all')
        w, h = max(120,self.winfo_width())-1, max(70,self.winfo_height())-1
        edge = TEXT if self.selected or self.focus_get() is self else BORDER
        self.create_polygon(1,1,w-11,1,w,12,w,h,11,h,1,h-11,
                            fill=CARD if self.selected else INPUT, outline=edge)
        self.create_text(16,30,text=self.goal['title'],anchor='w',fill=TEXT,font=(FONT,12,'bold'))
        self.create_text(16,68,text=self.goal['detail'],width=w-34,anchor='w',
                         fill=MUTED,font=(FONT,9))
        if self.selected:
            self.create_line(w-29,18,w-25,22,w-17,13,fill=RED,width=2)
            self.create_line(1,20,1,h-16,fill=RED,width=2)


class GuidedMixin:
    def build_guided(self, parent):
        from .gui import frame, label, button
        self.goal_cards={}
        self.guided_status=tk.StringVar(value='Add a memory image to get started.')
        self.guided_scope=tk.StringVar()
        self.guided_ready=tk.StringVar(value='Choose a goal. No analysis starts until you press Run.')
        self.guided_limit=tk.StringVar()
        actions=frame(parent,CARD)
        actions.pack(side='bottom',fill='x',pady=(10,0))
        self.guided_run_button=button(actions,'Run investigation',self.guided_run,True)
        self.guided_run_button.pack(side='right',padx=16,pady=12)
        button(actions,'Review plan',self.guided_review).pack(side='right',padx=(8,0))
        status=label(actions,textvariable=self.guided_ready,size=9,color=MUTED,bg=CARD,anchor='w',justify='left',wraplength=490)
        status.pack(side='left',fill='x',expand=True,padx=16,pady=10)
        status.bind('<Configure>',lambda e:status.configure(wraplength=max(180,e.width)))
        self.goal_scroll=VerticalPage(parent)
        self.goal_scroll.pack(fill='both',expand=True)
        body=self.goal_scroll.body
        strip=frame(body); strip.pack(fill='x',pady=(0,10))
        label(strip,'01  EVIDENCE   /   02  INVESTIGATE   /   03  REVIEW',size=8,color=MUTED,font=(MONO,8)).pack(side='left')
        case=frame(body,CARD);case.pack(fill='x',pady=(0,12))
        state=label(case,textvariable=self.guided_status,bg=CARD,size=10,anchor='w',justify='left',wraplength=880)
        state.pack(fill='x',padx=14,pady=12)
        state.bind('<Configure>',lambda e:state.configure(wraplength=max(260,e.width)))
        row=frame(body);row.pack(fill='x',pady=(0,8))
        label(row,'What are you investigating?',size=18,bold=True).pack(side='left')
        self.goal_grid=frame(body);self.goal_grid.pack(fill='x')
        for i,goal in enumerate(GOALS):
            card=GoalCard(self.goal_grid,goal,self.select_goal)
            card.grid(row=i//3,column=i%3,sticky='nsew',padx=(0,10 if i%3<2 else 0),pady=(0,9))
            self.goal_grid.columnconfigure(i%3,weight=1,uniform='goals')
            self.goal_cards[goal['profile']]=card
        label(body,textvariable=self.guided_scope,size=10,bold=True,anchor='w').pack(fill='x',pady=(6,3))
        limit=label(body,textvariable=self.guided_limit,size=9,color=MUTED,anchor='w',justify='left',wraplength=900)
        limit.pack(fill='x',pady=(0,12));limit.bind('<Configure>',lambda e:limit.configure(wraplength=max(260,e.width)))
        label(body,'OPTIONAL SEARCH TERMS / IPs, domains, paths or filenames; comma-separated',size=8,color=MUTED,font=(MONO,8)).pack(anchor='w',pady=(0,4))
        ttk.Entry(body,textvariable=self.terms_var).pack(fill='x',pady=(0,8))
        label(body,'Network and domain terms use boundary-aware matching. Other text uses literal matching. No external lookup.',size=8,color=MUTED,wraplength=900,justify='left').pack(anchor='w',pady=(0,10))
        self.refresh_guided()

    def select_goal(self, profile):
        if self.busy:
            return
        self.profile_var.set(profile)
        self.apply_profile(quiet=True)
        self.refresh_guided()
        self.status_var.set('Selected '+goal_details(profile)['title']+'. Review scope, then run when ready.')

    def refresh_guided(self):
        if not hasattr(self,'goal_cards'):
            return
        state=(self.profile_var.get(),len(self.checked_plugins),tuple(self.profile_missing),self.busy,
               self.case.root if self.case else None,len(self.catalog.get('plugins',[])),self.settings.offline)
        if getattr(self,'_guided_last_state',None)==state:return
        self._guided_last_state=state
        goal=goal_details(self.profile_var.get())
        for profile,card in self.goal_cards.items():
            card.selected=profile==self.profile_var.get()
            card.draw()
        self.guided_scope.set(goal['question'])
        self.guided_limit.set(goal['limit'])
        if self.case:
            m=self.case.metadata
            self.guided_status.set(str(m.get('name',m.get('id','Case')))+'  /  '+m.get('evidence_os','Unknown')+' capture  /  '+PathName(m.get('image','')))
        else:
            self.guided_status.set('No case open. Choose Add memory above, or reopen a preserved case.')
        n=len(self.checked_plugins); gaps=len(self.profile_missing)
        detail=f'{n} plugins selected' + (f' / {gaps} unavailable; review coverage' if gaps else '')
        detail+='\n'+('Symbol downloads allowed' if not self.settings.offline else 'Local symbols only')+' / Original output retained'
        if self.busy:
            detail='Investigation in progress. Open Live run to follow execution.'
        elif not self.catalog.get('plugins'):
            detail='Engine not ready. Open Settings or use the clean installer.'
        elif not self.case:
            detail='Add memory to start. You can choose a goal now.'
        self.guided_ready.set(detail)
        self.guided_run_button.configure(state='normal' if self.case and not self.busy and n else 'disabled')

    def open_advanced(self):
        self.mode_tabs.select(self.advanced_plan)

    def guided_run(self):
        self.run_checked()

    def guided_review(self):
        self.review_checked()


def PathName(value):
    from pathlib import Path
    return Path(value).name if value else 'Image selected'
