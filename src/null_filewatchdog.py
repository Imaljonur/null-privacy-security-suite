
LABELS = {
    "TITLE": "∅ File Watchdog",
    "SUB": "Monitor folders & log events",
    "ADD_FOLDER": "Add folder",
    "CLEAR_LOG": "Clear log",
    "ACTIONS": "Actions",
    "DELETE": "Delete",
    "DETAILS": "Details",
    "NOTE": "Tip: Click a row in the log list to select the file.",
    "STATUS": "Status",
    "MET_PATHS": "Watched folders",
    "MET_EVENTS": "Events",
    "MET_SELECTED": "Selected",
    "MET_STATE": "State",
    "WATCHING": "[Watching]",
    "NEW": "[NEW]",
    "MOD": "[MODIFIED]",
    "DEL": "[DELETED]",
    "SELECTED": "[Selected]",
    "DELETED_FILE": "[File deleted]",
    "DETAILS": "[Details]",
    "SIZE": "Size",
    "MOD_AT": "Modified",
    "ERR": "Error",
    "ERR_WATCH": "Could not watch folder.",
    "ERR_SELECT": "Error beim Auswählen:",
    "ERR_DELETE": "Error beim Delete:",
    "ERR_START": "Observer could not be started.",
    "NO_FILE": "No file selected or file does not exist.",
    "PREFIXES": ["[NEW]", "[MODIFIED]", "[DELETED]", "[Watching]", "[Selected]"],
}

import time
import os
import customtkinter as ctk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tkinter import filedialog, messagebox
import threading

# ---- Sentinel UDP (realtime, no GUI changes) ----
import os, json, socket
from datetime import datetime, timezone

SENT_HOST = os.environ.get("NULL_SENTINEL_HOST", "127.0.0.1")
SENT_PORT = int(os.environ.get("NULL_SENTINEL_PORT", "5140"))
_SENT_SOCK = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def _utcnow_iso():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()

def sentinel(ev: dict):
    try:
        _SENT_SOCK.sendto(json.dumps(ev, ensure_ascii=False).encode("utf-8"), (SENT_HOST, SENT_PORT))
    except Exception:
        pass

ACCENT        = "#00FF88"
BG_DARK       = "#0B0F10"
BG_CARD       = "#12171A"
FG_TEXT       = "#D7E0E6"
FG_MUTED      = "#8FA3AD"
FG_OK         = "#7CE38B"
FG_BAD        = "#FF5C7C"
FG_WARN       = "#FFCC66"
BORDER        = "#1D252B"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, log_callback, labels):
        self.log = log_callback
        self.L = labels

    def on_created(self, event):
        if event.is_directory: return
        ext = os.path.splitext(event.src_path)[1].lower()
        if ext in [".exe", ".dll", ".bat", ".ps1"]:
            self.log(f"{self.L['NEW']} {event.src_path}", "yellow")

    def on_modified(self, event):
        if event.is_directory: return
        self.log(f"{self.L['MOD']} {event.src_path}", "orange")

        sentinel({
            "ts": _utcnow_iso(),
            "tool": "filewatchdog",
            "level": "warn",
            "host": "",
            "pid": 0,
            "msg": f"file modified: {event.src_path}",
            "labels": {"file": event.src_path, "action": "modified"}
        })
    def on_deleted(self, event):
        if event.is_directory: return
        self.log(f"{self.L['DEL']} {event.src_path}", "red")

        sentinel({
            "ts": _utcnow_iso(),
            "tool": "filewatchdog",
            "level": "info",
            "host": "",
            "pid": 0,
            "msg": f"file deleted: {event.src_path}",
            "labels": {"file": event.src_path, "action": "deleted"}
        })
class FileWatcherApp(ctk.CTk):
    def __init__(self, labels):
        super().__init__()
        self.title(labels['TITLE'])
        self.geometry("980x680")
        self.configure(fg_color=BG_DARK)
        self.L = labels

        # State
        self.observer = Observer()
        self.watch_paths = set()
        self.selected_file = None
        self.events = 0
        self.running = False

        # Layout grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._build_statusbar()

        # Handler
        self.handler = FileEventHandler(self._log, labels)

        # Defaults: Downloads + Startup (if exists)
        try:
            downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            if os.path.isdir(downloads):
                self._add_watch(downloads)
            startup = os.path.join(os.environ.get("APPDATA",""), r"Microsoft\Windows\Start Menu\Programs\Startup")
            if os.path.isdir(startup):
                self._add_watch(startup)
        except Exception:
            pass

        # Start observer
        self._start_observer()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(150, self._tick)

    # ---------- UI ----------
    def _card(self, parent):
        return ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=14, border_color=BORDER, border_width=1)

    def _build_sidebar(self):
        sb = self._card(self)
        sb.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        sb.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(sb, text=self.L['TITLE'], text_color=ACCENT, font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        ctk.CTkLabel(sb, text=self.L['SUB'], text_color=FG_MUTED).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

        self.btn_add = ctk.CTkButton(sb, text=self.L['ADD_FOLDER'], command=self._add_folder, fg_color=ACCENT, text_color="black")
        self.btn_add.grid(row=2, column=0, padx=16, pady=(4,8), sticky="ew")

        self.btn_clear = ctk.CTkButton(sb, text=self.L['CLEAR_LOG'], command=self._clear_log, fg_color="#1F2933", hover_color="#25313B")
        self.btn_clear.grid(row=3, column=0, padx=16, pady=(0,8), sticky="ew")

        actions = self._card(sb)
        actions.grid(row=4, column=0, padx=16, pady=(0,12), sticky="ew")
        ctk.CTkLabel(actions, text=self.L['ACTIONS'], text_color=FG_MUTED).pack(anchor="w", padx=10, pady=(8,2))
        ctk.CTkButton(actions, text=self.L['DELETE'], command=self._delete_selected, fg_color="#B84C4C", hover_color="#A03E3E").pack(fill="x", padx=10, pady=(0,6))
        ctk.CTkButton(actions, text=self.L['DETAILS'], command=self._show_details, fg_color="#1F2933", hover_color="#25313B").pack(fill="x", padx=10, pady=(0,10))

        self.lbl_note = ctk.CTkLabel(sb, text=self.L['NOTE'], text_color=FG_MUTED, wraplength=230, font=ctk.CTkFont(size=12))
        self.lbl_note.grid(row=5, column=0, padx=16, pady=(0,12), sticky="w")

    def _build_main(self):
        main = self._card(self)
        main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(main, fg_color=BG_CARD)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
        header.grid_columnconfigure(0, weight=1)
        self.state_label = ctk.CTkLabel(header, text=f"{self.L['STATUS']}: idle", text_color=FG_MUTED)
        self.state_label.grid(row=0, column=0, sticky="w")
        self.time_label = ctk.CTkLabel(header, text="", text_color=FG_MUTED)
        self.time_label.grid(row=0, column=1, sticky="e")

        body = ctk.CTkFrame(main, fg_color=BG_CARD)
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self.log_box = ctk.CTkTextbox(body, width=940, height=520)
        self.log_box.grid(row=0, column=0, sticky="nsew")
        self.log_box.bind("<ButtonRelease-1>", self._on_text_click)
        vsb = ctk.CTkScrollbar(body, command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=vsb.set)
        vsb.grid(row=0, column=1, sticky="ns")

    def _build_statusbar(self):
        st = self._card(self)
        st.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
        st.grid_columnconfigure((0,1,2,3), weight=1)

        def metric(label, value):
            box = ctk.CTkFrame(st, fg_color=BG_CARD)
            title = ctk.CTkLabel(box, text=label, text_color=FG_MUTED, font=ctk.CTkFont(size=12))
            val   = ctk.CTkLabel(box, text=value, text_color=ACCENT, font=ctk.CTkFont(size=18, weight="bold"))
            title.pack(anchor="center", pady=(8,0))
            val.pack(anchor="center", pady=(0,8))
            return box, val

        self.box_paths, self.lbl_paths   = metric(self.L['MET_PATHS'], "0")
        self.box_events, self.lbl_events = metric(self.L['MET_EVENTS'], "0")
        self.box_sel, self.lbl_sel       = metric(self.L['MET_SELECTED'], "0")
        self.box_state, self.lbl_state   = metric(self.L['MET_STATE'], "idle")

        self.box_paths.grid(row=0, column=0, sticky="ew", padx=(0,8))
        self.box_events.grid(row=0, column=1, sticky="ew", padx=8)
        self.box_sel.grid(row=0, column=2, sticky="ew", padx=8)
        self.box_state.grid(row=0, column=3, sticky="ew", padx=(8,0))

    # ---------- Logging & helpers ----------
    def _log(self, text, color=FG_OK):
        tag = color
        try:
            self.log_box.insert("end", f"{time.strftime('%H:%M:%S')} | {text}\n", (tag,))
            self.log_box.tag_config(tag, foreground=color)
            self.log_box.see("end")
        except Exception:
            pass
        self.events += 1
        self.lbl_events.configure(text=str(self.events))

    def _clear_log(self):
        try:
            self.log_box.delete("1.0","end")
        except Exception:
            pass

    def _add_folder(self):
        folder = filedialog.askdirectory()
        if folder and folder not in self.watch_paths:
            self._add_watch(folder)
            self._log(f"{self.L['WATCHING']} {folder}", FG_WARN)

    def _add_watch(self, path):
        try:
            self.observer.schedule(self.handler, path, recursive=True)
            self.watch_paths.add(path)
            self.lbl_paths.configure(text=str(len(self.watch_paths)))
        except Exception as e:
            messagebox.showerror(self.L['ERR'], f"{self.L['ERR_WATCH']}\\n{e}")

    def _on_text_click(self, event):
        try:
            index = self.log_box.index("insert linestart")
            line = self.log_box.get(index, f"{index} lineend")
            if any(prefix in line for prefix in self.L['PREFIXES']):
                filepath = line.split(" ", 1)[-1].strip()
                if os.path.exists(filepath):
                    self.selected_file = filepath
                    self._log(f"{self.L['SELECTED']} {filepath}", FG_WARN)
                    self.lbl_sel.configure(text="1")
        except Exception as e:
            self._log(f"{self.L['ERR_SELECT']} {e}", FG_BAD)

    def _delete_selected(self):
        if self.selected_file and os.path.exists(self.selected_file):
            try:
                os.remove(self.selected_file)
                self._log(f"{self.L['DELETED_FILE']} {self.selected_file}", "yellow")
                self.selected_file = None
                self.lbl_sel.configure(text="0")
            except Exception as e:
                self._log(f"{self.L['ERR_DELETE']} {e}", FG_BAD)
        else:
            self._log(self.L['NO_FILE'], FG_BAD)

    def _show_details(self):
        if self.selected_file and os.path.exists(self.selected_file):
            size = os.path.getsize(self.selected_file)
            mtime = time.ctime(os.path.getmtime(self.selected_file))
            self._log(f"{self.L['DETAILS']} {self.selected_file}\\n{self.L['SIZE']}: {size} B\\n{self.L['MOD_AT']}: {mtime}", FG_MUTED)
        else:
            self._log(self.L['NO_FILE'], FG_BAD)

    def _start_observer(self):
        if self.running: return
        try:
            self.observer.start()
            self.running = True
            self._set_state("running")
        except Exception as e:
            messagebox.showerror(self.L['ERR'], f"{self.L['ERR_START']}\\n{e}")
            self._set_state("error")

    def _set_state(self, state):
        self.lbl_state.configure(text=state)
        self.state_label.configure(text=f"{self.L['STATUS']}: {state}")
        if state == "running":
            self.state_label.configure(text_color=ACCENT)
        elif state == "error":
            self.state_label.configure(text_color=FG_BAD)
        else:
            self.state_label.configure(text_color=FG_MUTED)

    def _on_close(self):
        try:
            if self.running:
                self.observer.stop()
                self.observer.join()
        except Exception:
            pass
        self.destroy()

    def _tick(self):
        self.time_label.configure(text=time.strftime("%Y-%m-%d %H:%M:%S"))
        self.after(250, self._tick)

if __name__ == "__main__":
    app = FileWatcherApp(LABELS)
    app.mainloop()
