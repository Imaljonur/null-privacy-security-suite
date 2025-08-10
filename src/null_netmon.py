
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import psutil
import threading
import time
import csv
import os
from collections import defaultdict
import customtkinter as ctk

try:
    import requests
except ImportError:
    requests = None

# =========================
#  THEME (GUI ONLY CHANGE)
# =========================
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
#  ORIGINAL LOGIC (UNCHANGED)
# =========================

def ai_threat_check(proc, rip, country, port, data_sent, org, conn_counts, warn_output):
    messages = []
    if not rip:
        return
    conn_counts[rip] += 1
    if conn_counts[rip] > 20:
        messages.append(f"[AI] 🧠 Possible port scan: {conn_counts[rip]} Verbindungen nach {rip} durch {proc}")
    if country == "?" and org == "?" and not rip.startswith("192.168"):
        messages.append(f"[AI] ❓ Target anonymous & unknown: {rip} von {proc}")
    if proc.lower() in SUSPICIOUS_PROCESSES and data_sent != "-" and isinstance(data_sent, int) and data_sent > 10**7:
        messages.append(f"[AI] 🔥 Unusual traffic: {proc} sendet {round(data_sent/1_000_000,1)} MB")
    for msg in messages:
        warn_output.configure(text=msg)

BLACKLIST_COUNTRIES = {"CN", "RU", "IR", "KP"}
SUSPICIOUS_PROCESSES = {"powershell.exe", "cmd.exe", "python.exe", "wscript.exe", "cscript.exe", "java.exe"}
EXPORT_LOG = []

scan_tracker = defaultdict(list)
scan_threshold = 10
refresh_interval = 3
paused = False
latest_warning = ''

def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def get_geo_ip(ip):
    if requests:
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
            if r.status_code == 200:
                data = r.json()
                return data.get("org", "?"), data.get("country", "?")
        except:
            pass
    return "?", "?"

def get_traffic(pid):
    try:
        p = psutil.Process(pid)
        net_io = p.io_counters()
        return net_io.read_bytes + net_io.write_bytes
    except:
        return 0

def detect_scan(ip, port):
    t = time.time()
    scan_tracker[ip].append((t, port))
    scan_tracker[ip] = [(ts, p) for ts, p in scan_tracker[ip] if t - ts < 5]
    return len(set(p for _, p in scan_tracker[ip])) > scan_threshold

def update_connections(tree, warn_label, interval_var, warn_output):
    global paused
    global refresh_interval
    seen = set()
    conn_counts = defaultdict(int)
    while True:
        try:
            refresh_interval = int(interval_var.get())
        except:
            refresh_interval = 3
        if paused:
            time.sleep(refresh_interval)
            continue
        conns = psutil.net_connections(kind='inet')
        rows = []
        suspicious_count = 0
        for conn in conns:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            rip = conn.raddr.ip if conn.raddr else ""
            port = conn.raddr.port if conn.raddr else 0
            status = conn.status
            pid = conn.pid
            proc = "?"
            host = ""
            geo = ""
            org = "?"
            country = "?"
            data_sent = "-"
            flags = ""
            if pid:
                try:
                    p = psutil.Process(pid)
                    proc = p.name()
                    data_sent = get_traffic(pid)
                except:
                    pass
            if rip:
                host = resolve_ip(rip)
                org, country = get_geo_ip(rip)
                geo = f"{org} / {country}"
                if detect_scan(rip, port):
                    flags += "🧠"
            if (country in BLACKLIST_COUNTRIES or country == "?") and not paused:
                global latest_warning
                latest_warning = f"[ALARM] ⚠️ Connection to {country}: {rip}:{port} ({proc})"
                warn_output.configure(text=latest_warning)
            if country in BLACKLIST_COUNTRIES or country == "?":
                flags += "⚠️"
            if proc.lower() in SUSPICIOUS_PROCESSES:
                flags += "🔥"
            row = (flags + proc, laddr, raddr, host, geo, status, data_sent)
            rows.append(row)
            ai_threat_check(proc, rip, country, port, data_sent, org, conn_counts, warn_output)
            EXPORT_LOG.append((time.strftime("%Y-%m-%d %H:%M:%S"), *row))
            if "⚠️" in flags or "🧠" in flags or "🔥" in flags:
                suspicious_count += 1
        rows.sort()
        for row in rows:
            tree.insert("", "end", values=row, tags=("warn",) if any(x in row[0] for x in "⚠️🧠🔥") else ())
        warn_label.configure(text=f"⚠️ Suspicious activity: {suspicious_count}")
        time.sleep(refresh_interval)

def export_csv():
    if not EXPORT_LOG:
        messagebox.showinfo("Export", "No data to export.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")])
    if file:
        with open(file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Program", "Local", "Remote", "Domain", "Geo", "Status", "Traffic(Bytes)"])
            for row in EXPORT_LOG:
                writer.writerow(row)
        messagebox.showinfo("Export", f"Saved: {os.path.basename(file)}")

# =========================
#  NEW GUI ONLY (ctk)
# =========================
def main():
    _theme_setup()
    root = ctk.CTk()
    root.title("∅null Network Monitor")
    root.geometry("1300x720")
    root.configure(fg_color=BG_DARK)

    root.grid_columnconfigure(0, weight=0)
    root.grid_columnconfigure(1, weight=1)
    root.grid_rowconfigure(0, weight=1)
    root.grid_rowconfigure(1, weight=0)

    # Sidebar
    sidebar = _card(root)
    sidebar.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
    sidebar.grid_columnconfigure(0, weight=1)

    _title(sidebar, "∅ NetMon").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
    _label(sidebar, "Live connections + heuristics", muted=True).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

    # Controls group
    controls = _card(sidebar); controls.grid(row=2, column=0, padx=16, pady=(0,12), sticky="ew")
    controls.grid_columnconfigure((0,1,2), weight=1)

    # Refresh interval
    _label(controls, "🔄 Refresh [s]:", muted=True).grid(row=0, column=0, padx=10, pady=10, sticky="w")
    interval_var = tk.StringVar(value=str(refresh_interval))
    interval_entry = ttk.Combobox(controls, textvariable=interval_var, values=["1","2","3","5","10"], width=6)
    interval_entry.grid(row=0, column=1, padx=6, pady=10, sticky="w")

    # Freeze/Resume
    def toggle_pause():
        global paused
        paused = not paused
        btn_pause.configure(text="🟢 Resume" if paused else "⏸️ Freeze")
    btn_pause = _btn_subtle(controls, "⏸️ Freeze", toggle_pause)
    btn_pause.grid(row=0, column=2, padx=8, pady=10, sticky="ew")

    # Export
    _btn_primary(sidebar, "📁 Save history", export_csv).grid(row=3, column=0, padx=16, pady=(0,16), sticky="ew")

    # Main card
    main_card = _card(root)
    main_card.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
    main_card.grid_columnconfigure(0, weight=1)
    main_card.grid_rowconfigure(1, weight=1)

    # Header
    header = ctk.CTkFrame(main_card, fg_color=BG_CARD)
    header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
    header.grid_columnconfigure(0, weight=1)
    warn_label = _label(header, "⚠️ Suspicious activity: 0", muted=True)
    warn_label.grid(row=0, column=0, sticky="w")

    # Body with tree
    body = ctk.CTkFrame(main_card, fg_color=BG_CARD)
    body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
    body.grid_columnconfigure(0, weight=1)
    body.grid_rowconfigure(0, weight=1)

    style = ttk.Style()
    try: style.theme_use("clam")
    except: pass
    style.configure("Treeview",
                    background=BG_CARD, fieldbackground=BG_CARD,
                    foreground=FG_TEXT, rowheight=26, font=("Consolas", 10))
    style.map('Treeview', background=[('selected', '#23313A')])
    style.configure("Treeview.Heading",
                    background=BG_CARD, foreground=ACCENT,
                    font=("Consolas", 10, "bold"))

    columns = ("Program", "Local address", "Remote address", "Domain", "Geo / Provider", "Status", "Traffic(Bytes)")
    tree = ttk.Treeview(body, columns=columns, show="headings", selectmode="browse")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, anchor="w", width=170 if col=="Program" else 160)
    tree.grid(row=0, column=0, sticky="nsew")

    vsb = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.grid(row=0, column=1, sticky="ns")

    tree.tag_configure("warn", background="#3A2020", foreground="#FF8080")

    # Statusbar
    statusbar = _card(root)
    statusbar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
    statusbar.grid_columnconfigure(0, weight=1)
    warn_output = _label(statusbar, "", muted=False)
    warn_output.grid(row=0, column=0, padx=12, pady=10, sticky="w")

    # Start worker
    threading.Thread(target=update_connections, args=(tree, warn_label, interval_var, warn_output), daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    main()
