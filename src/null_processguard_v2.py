
import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import time
import threading
import os

SUSPICIOUS_PATTERNS = ["powershell", "cmd.exe", "curl", "wget", "base64", "whoami", "reg add", "schtasks", "-enc", "-e"]
paused = False

# === Erweiterungen: Lokale Forensik-Erkennung ===
import tkinter.messagebox as msgbox
import datetime

seen_pids = set()

def log_suspicious_process(p, reason):
    global seen_pids
    if p.pid in seen_pids:
        return
    seen_pids.add(p.pid)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] Suspicious process detected: {p.name()} (PID {p.pid}) - Reason: {reason}\n"
    with open("suspicious_processes.log", "a", encoding="utf-8") as log_file:
        log_file.write(log_entry)
    try:
        msgbox.showwarning("Suspicious Process", log_entry)
    except:
        pass

KEYLOGGER_PATTERNS = [
    "hook", "keylog", "screenshot", "win32gui", "pyHook", "SendInput",
    "GetAsyncKeyState", "SetWindowsHookEx", "pynput", "keyboard.read_event",
    "socket(AF_INET, SOCK_RAW)"
]

def is_headless_windows(pid):
    if os.name != "nt":
        return False
    try:
        import win32gui
        found = []
        def cb(hwnd, _):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                _, found_pid = win32gui.GetWindowThreadProcessId(hwnd)
                if found_pid == pid:
                    found.append(True)
        win32gui.EnumWindows(cb, None)
        return not bool(found)
    except:
        return False

def scan_suspicious_ram(proc):
    try:
        for m in proc.memory_maps():
            if any(pat in m.path.lower() for pat in KEYLOGGER_PATTERNS):
                return True
    except:
        pass
    try:
        for arg in proc.cmdline():
            if any(pat in arg.lower() for pat in KEYLOGGER_PATTERNS):
                return True
    except:
        pass
    return False

# =========================
#  THEME (GUI ONLY CHANGE)
# =========================
import customtkinter as ctk

ACCENT        = "#00FF88"
BG_DARK       = "#0B0F10"
BG_CARD       = "#12171A"
FG_TEXT       = "#D7E0E6"
FG_MUTED      = "#8FA3AD"
BORDER        = "#1D252B"

def _theme_setup():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("green")

def _card(parent, **kwargs):
    opts = dict(fg_color=BG_CARD, corner_radius=14, border_color=BORDER, border_width=1)
    opts.update(kwargs)
    return ctk.CTkFrame(parent, **opts)

def _title(parent, text):
    return ctk.CTkLabel(parent, text=text, text_color=ACCENT, font=ctk.CTkFont(size=20, weight="bold"))

def _label(parent, text, muted=False):
    return ctk.CTkLabel(parent, text=text, text_color=(FG_MUTED if muted else FG_TEXT))

def _btn_primary(parent, text, command=None):
    return ctk.CTkButton(parent, text=text, fg_color=ACCENT, text_color="black", command=command)

def _btn_subtle(parent, text, command=None):
    return ctk.CTkButton(parent, text=text, fg_color="#1F2933", hover_color="#25313B", command=command)

# =========================
#  ORIGINAL SCAN / LOGIC (UNCHANGED)
# =========================
def scan_processes(tree, warn_label):
    global paused
    while True:
        if paused:
            time.sleep(2)
            continue
        for item in tree.get_children():
            tree.delete(item)
        procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "exe", "cmdline"]):
            try:
                pid = p.info["pid"]
                name = p.info["name"]
                cpu_raw = p.info["cpu_percent"]
                cpu = f"{cpu_raw:.1f}%"
                mem = p.info["memory_info"].rss // (1024 * 1024)
                exe = p.info.get("exe") or "?"
                cmdline = " ".join(p.info.get("cmdline") or [])
                suspicious = any(x.lower() in cmdline.lower() for x in SUSPICIOUS_PATTERNS)
                headless = is_headless_windows(pid)
                ram_suspicious = scan_suspicious_ram(p)
                suspicious = suspicious or ram_suspicious or headless

                if ram_suspicious:
                    log_suspicious_process(p, "RAM/Cmdline pattern match")
                if headless:
                    log_suspicious_process(p, "Headless process (no visible window)")

                procs.append((pid, name, cpu, f"{mem} MB", exe, cmdline, suspicious, cpu_raw))
            except:
                continue
        procs.sort(key=lambda x: x[7], reverse=True)
        count = 0
        for pid, name, cpu, mem, exe, cmd, suspicious, _ in procs:
            tag = "warn" if suspicious else ""
            tree.insert("", "end", values=(pid, name, cpu, mem, exe, cmd), tags=(tag,))
            if suspicious:
                count += 1
        # CustomTkinter uses .configure instead of .config
        warn_label.configure(text=f"⚠️ Suspicious processes: {count}")
        time.sleep(2)

def kill_selected(tree):
    sel = tree.selection()
    if not sel:
        return
    for item in sel:
        pid = tree.item(item)["values"][0]
        try:
            psutil.Process(pid).kill()
            messagebox.showinfo("Done", f"Process {pid} has been terminated.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# =========================
#  NEW GUI ONLY (ctk) – Logic unchanged
# =========================
def main():
    global paused
    _theme_setup()
    root = ctk.CTk()
    root.title("∅null ProcessGuard")
    root.geometry("1300x720")
    root.configure(fg_color=BG_DARK)

    # Grid: Sidebar | Main
    root.grid_columnconfigure(0, weight=0)
    root.grid_columnconfigure(1, weight=1)
    root.grid_rowconfigure(0, weight=1)
    root.grid_rowconfigure(1, weight=0)

    # Sidebar
    sidebar = _card(root)
    sidebar.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
    sidebar.grid_columnconfigure(0, weight=1)

    _title(sidebar, "∅ ProcessGuard").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
    _label(sidebar, "Live process analysis + heuristics", muted=True).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

    # Buttons
    def toggle_pause():
        global paused
        paused = not paused
        pause_btn.configure(text="🟢 Resume" if paused else "⏸️ Freeze")

    pause_btn = _btn_subtle(sidebar, "⏸️ Freeze", toggle_pause)
    pause_btn.grid(row=2, column=0, padx=16, pady=(0,8), sticky="ew")

    kill_btn = _btn_primary(sidebar, "🧨 Kill process", lambda: kill_selected(tree))
    kill_btn.grid(row=3, column=0, padx=16, pady=(0,16), sticky="ew")

    # Main Card
    main_card = _card(root)
    main_card.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
    main_card.grid_columnconfigure(0, weight=1)
    main_card.grid_rowconfigure(1, weight=1)

    header = ctk.CTkFrame(main_card, fg_color=BG_CARD)
    header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
    header.grid_columnconfigure(0, weight=1)
    warn_label = _label(header, "⚠️ Suspicious processes: 0", muted=True)
    warn_label.grid(row=0, column=0, sticky="w")

    # Body with Treeview
    body = ctk.CTkFrame(main_card, fg_color=BG_CARD)
    body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
    body.grid_columnconfigure(0, weight=1)
    body.grid_rowconfigure(0, weight=1)

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except:
        pass
    style.configure("Treeview",
                    background=BG_CARD,
                    foreground=FG_TEXT,
                    rowheight=26,
                    fieldbackground=BG_CARD,
                    font=("Consolas", 10))
    style.map('Treeview', background=[('selected', '#23313A')])
    style.configure("Treeview.Heading",
                    background=BG_CARD,
                    foreground=ACCENT,
                    font=("Consolas", 10, "bold"))

    columns = ("PID", "Name", "CPU", "RAM", "Pfad", "Commandline")
    tree = ttk.Treeview(body, columns=columns, show="headings", selectmode="browse")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, anchor="w", width=160)
    tree.grid(row=0, column=0, sticky="nsew")

    vsb = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.grid(row=0, column=1, sticky="ns")

    tree.tag_configure("warn", background="#440000", foreground="#FF6666")

    # Statusbar
    statusbar = _card(root)
    statusbar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
    statusbar.grid_columnconfigure(0, weight=1)
    _label(statusbar, "Tip: Freeze if needed – Kill ends the selected process.", muted=True).grid(row=0, column=0, padx=12, pady=10, sticky="w")

    threading.Thread(target=scan_processes, args=(tree, warn_label), daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    main()
