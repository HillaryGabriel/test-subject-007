"""Quiet, high-contrast desktop theme. No external fonts, bitmaps or assets."""
from __future__ import annotations
import os
import tkinter as tk

BG = '#101012'
SIDE = '#121214'
CARD = '#19191c'
INPUT = '#141416'
BORDER = '#343438'
TEXT = '#eeeef0'
MUTED = '#a0a0a8'
ACCENT = '#e5e5e8'
DARK_ACCENT = '#2b2b30'
RED = '#d95b65'
GOOD = '#a6bda9'
WARN = '#d8ba83'
FONT = 'Segoe UI' if os.name == 'nt' else 'DejaVu Sans'
MONO = 'Consolas' if os.name == 'nt' else 'DejaVu Sans Mono'


class CutPanel(tk.Frame):
    """One clipped corner and hairline frame, with an ordinary Tk content area."""
    def __init__(self, master, accent=False, **kwargs):
        super().__init__(master, bg=BG, **kwargs)
        self.accent = accent
        self.outline = tk.Canvas(self, bg=BG, highlightthickness=0, bd=0)
        self.outline.place(x=0, y=0, relwidth=1, relheight=1)
        self.body = tk.Frame(self, bg=CARD)
        self.body.pack(fill='both', expand=True, padx=13, pady=13)
        self.bind('<Configure>', self._draw)

    def _draw(self, event):
        w, h = event.width - 1, event.height - 1
        self.outline.delete('all')
        self.outline.create_polygon(12, 1, w, 1, w, h-12, w-12, h, 1, h, 1, 12,
                                    fill=CARD, outline=BORDER, width=1)
        if self.accent:
            self.outline.create_line(1, 31, 1, 12, 12, 1, 42, 1, fill=TEXT, width=1)
            self.outline.create_line(w-35, h, w-12, h, w, h-12, fill=RED, width=1)


class MemoryGlyph(tk.Canvas):
    """Small static RAM outline; decorative, never an analytical visualization."""
    def __init__(self, master, **kwargs):
        super().__init__(master, width=124, height=78, bg=CARD, highlightthickness=0, **kwargs)
        self.create_line(10, 25, 10, 15, 20, 5, 34, 5, fill=BORDER)
        self.create_line(95, 71, 114, 71, 114, 55, fill=BORDER)
        self.create_rectangle(18, 22, 106, 54, outline=MUTED, width=1)
        for x in (26, 46, 66, 86):
            self.create_rectangle(x, 29, x+12, 46, outline=MUTED)
        for x in range(24, 104, 6):
            self.create_line(x, 54, x, 59, fill=MUTED)
        self.create_line(106, 22, 111, 17, 111, 49, 106, 54, fill=BORDER)
        self.create_line(18, 22, 23, 17, 111, 17, fill=BORDER)
        self.create_line(10, 65, 17, 65, fill=RED)


def set_windows_dark_titlebar(window):
    """Best-effort DWM titlebar; failure must never block Linux/Windows startup."""
    if os.name != 'nt':
        return
    try:
        import ctypes
        from ctypes import wintypes
        window.update_idletasks()
        user32 = ctypes.windll.user32
        user32.GetParent.argtypes = [wintypes.HWND]
        user32.GetParent.restype = wintypes.HWND
        hwnd = user32.GetParent(window.winfo_id())
        value = ctypes.c_int(1)
        setter = ctypes.windll.dwmapi.DwmSetWindowAttribute
        setter.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        for attribute in (20, 19):
            if setter(hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                break
    except (AttributeError, OSError, ValueError):
        pass


class VerticalPage(tk.Frame):
    """Keep packed controls reachable on shorter screens and larger DPI settings."""
    def __init__(self, master):
        from tkinter import ttk
        super().__init__(master, bg=BG)
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0, bd=0)
        self.bar = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.bar.set)
        self.canvas.grid(row=0, column=0, sticky='nsew')
        self.bar.grid(row=0, column=1, sticky='ns', padx=(6, 0))
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.body = tk.Frame(self.canvas, bg=BG)
        self.window = self.canvas.create_window(0, 0, window=self.body, anchor='nw')
        self.canvas.bind('<Configure>', self._sync)
        self.body.bind('<Configure>', self._sync)

    def _sync(self, _=None):
        width = max(1, self.canvas.winfo_width())
        height = max(self.canvas.winfo_height(), self.body.winfo_reqheight())
        self.canvas.itemconfigure(self.window, width=width, height=height)
        self.canvas.configure(scrollregion=(0, 0, width, height))

    def scroll_event(self, event):
        if isinstance(event.widget, (tk.Text, tk.Listbox)) or event.widget.winfo_class() == 'Treeview':
            return
        if getattr(event, 'num', 0) in (4, 5):
            delta = -1 if event.num == 4 else 1
        else:
            delta = -1 if event.delta > 0 else 1
        self.canvas.yview_scroll(delta * 3, 'units')
