
import os
import sys
import json
import time
import socket
import queue
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

import customtkinter as ctk
import subprocess
import threading as _t

# =========================
#  THEME (GUI ONLY CHANGE)
# =========================
ACCENT        = "#00FF88"
BG_DARK       = "#0B0F10"
BG_CARD       = "#12171A"
FG_TEXT       = "#D7E0E6"

def _theme_setup():
    ctk.set_appearance_mode("dark")
    try:
        ctk.set_default_color_theme("green")
    except Exception:
        pass

def _card(parent, **kwargs):
    opts = dict(fg_color=BG_CARD, corner_radius=14)
    opts.update(kwargs)
    frame = ctk.CTkFrame(parent, **opts)
    return frame

def _title(parent, text):
    return ctk.CTkLabel(parent, text=text, text_color=ACCENT, font=ctk.CTkFont(size=18, weight="bold"))

def _label(parent, text):
    return ctk.CTkLabel(parent, text=text, text_color=FG_TEXT)

def _btn(parent, text, command=None):
    # Accent primary button, but keep original commands untouched
    return ctk.CTkButton(parent, text=text, fg_color=ACCENT, text_color="black", command=command)

# =========================
#  SIEM/EDR-Light (inline)
# =========================

def _utcnow_iso():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()

def _norm_event(raw):
    if isinstance(raw, str):
        try:
            d = json.loads(raw)
        except Exception:
            d = {"msg": raw}
    elif isinstance(raw, dict):
        d = raw.copy()
    else:
        d = {"msg": str(raw)}

    ev = {
        "ts": d.get("ts") or _utcnow_iso(),
        "tool": str(d.get("tool") or d.get("app") or "unknown"),
        "level": str(d.get("level") or d.get("severity") or "info").lower(),
        "host": str(d.get("host") or d.get("hostname") or os.environ.get("COMPUTERNAME") or ""),
        "pid": int(d.get("pid") or 0) if str(d.get("pid") or "").isdigit() else 0,
        "msg": str(d.get("msg") or d.get("message") or ""),
        "labels": d.get("labels") or {},
    }
    for k in ("ip","domain","proc","file","rule","port","commandline"):
        if k in d and k not in ev["labels"]:
            ev["labels"][k] = d[k]
    return ev

class EventCollector:
    """Tails JSONL files and listens on UDP for JSON events; persists to SQLite; exposes a Queue."""
    def __init__(self, db_path="sentinel.db", udp_host="127.0.0.1", udp_port=5140):
        self.db_path = db_path
        self.udp_host = udp_host
        self.udp_port = udp_port
        self.running = False
        self.files = []
        self.q = queue.Queue(maxsize=5000)
        self._threads = []
        self._lock = threading.Lock()
        self._conn = None

    def set_files(self, file_paths):
        self.files = [Path(p) for p in file_paths if p]

    def _connect(self):
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, tool TEXT, level TEXT, host TEXT, pid INTEGER, msg TEXT, labels TEXT
        )""")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, severity TEXT, title TEXT, details TEXT, tags TEXT
        )""")
        self._conn.commit()

    def _save_event(self, ev):
        try:
            with self._lock:
                self._conn.execute("INSERT INTO events(ts,tool,level,host,pid,msg,labels) VALUES(?,?,?,?,?,?,?)",
                                   (ev["ts"], ev["tool"], ev["level"], ev["host"], ev["pid"], ev["msg"], json.dumps(ev["labels"])))
                self._conn.commit()
        except Exception:
            pass

    def save_incident(self, inc):
        try:
            with self._lock:
                self._conn.execute("INSERT INTO incidents(ts,severity,title,details,tags) VALUES(?,?,?,?,?)",
                                   (inc["ts"], inc["severity"], inc["title"], json.dumps(inc.get("details",{})), ",".join(inc.get("tags",[]))))
                self._conn.commit()
        except Exception:
            pass

    def _tail_file(self, path: Path):
        try:
            f = path.open("r", encoding="utf-8", errors="ignore")
        except FileNotFoundError:
            return
        with f:
            f.seek(0, os.SEEK_END)
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.5); continue
                ev = _norm_event(line.strip())
                self._save_event(ev)
                try: self.q.put_nowait(ev)
                except queue.Full: pass

    def _udp_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((self.udp_host, self.udp_port))
        except OSError:
            return
        sock.settimeout(1.0)
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                ev = _norm_event(data.decode("utf-8", errors="ignore"))
                if not ev.get("host"):
                    ev["host"] = addr[0]
                self._save_event(ev)
                self.q.put_nowait(ev)
            except Exception:
                pass
        try: sock.close()
        except Exception: pass

    def start(self):
        if self.running:
            return
        self.running = True
        self._connect()
        for p in self.files:
            t = threading.Thread(target=self._tail_file, args=(p,), daemon=True)
            t.start(); self._threads.append(t)
        t = threading.Thread(target=self._udp_server, daemon=True)
        t.start(); self._threads.append(t)

    def stop(self):
        self.running = False

class RuleEngine:
    """Very small in-memory correlator for 3 demo rules."""
    def __init__(self, collector: EventCollector):
        self.c = collector
        self.buffer = []
        self.max_buffer = 2000
        self.bad_domains = set()
        self.tor_exit = set()
        self._load_lists()

    def _load_lists(self):
        def _load(path):
            p = Path(path)
            if not p.exists(): return []
            try:
                return [x.strip() for x in p.read_text(encoding="utf-8").splitlines() if x.strip() and not x.strip().startswith("#")]
            except Exception:
                return []
        self.bad_domains = set(_load("rules/bad_domains.txt"))
        self.tor_exit = set(_load("rules/tor_exit_ips.txt"))

    def add(self, ev: dict):
        self.buffer.append(ev)
        if len(self.buffer) > self.max_buffer:
            self.buffer = self.buffer[-self.max_buffer:]

    def _within(self, seconds, predicate):
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        out = []
        for e in reversed(self.buffer):
            try:
                ts = datetime.fromisoformat(e["ts"].replace("Z","+00:00")).replace(tzinfo=timezone.utc)
            except Exception:
                continue
            if ts < cutoff:
                break
            if predicate(e):
                out.append(e)
        return out

    def correlate(self, ev):
        incs = []
        # R-1001: Honeytoken + Outbound IP
        if "ip" in ev.get("labels",{}) and ev.get("tool") in ("ai_watchdog","netmon"):
            prior = self._within(300, lambda e: e.get("labels",{}).get("rule")=="honeytoken_open")
            if prior:
                incs.append({"ts": _utcnow_iso(), "severity":"high", "title":"Honeytoken gelesen + Outbound",
                             "details":{"current":ev, "supporting": prior[:5]}, "tags":["exfil","honeytoken"]})
        # R-1002: DNS bad domain + PowerShell base64
        if ev.get("tool")=="dnswatcher" and ev.get("labels",{}).get("domain") in self.bad_domains:
            hit = self._within(600, lambda e: e.get("tool")=="processguard" and e.get("labels",{}).get("proc","").lower()=="powershell.exe" and ("base64" in e.get("msg","").lower() or " -enc " in e.get("msg","").lower()))
            if hit:
                incs.append({"ts": _utcnow_iso(), "severity":"medium", "title":"Suspicious DNS + PowerShell b64",
                             "details":{"current":ev, "supporting": hit[:5]}, "tags":["lateral","script"]})
        # R-1003: TOR exit + unusual proc
        lbl = ev.get("labels",{})
        if ev.get("tool") in ("ai_watchdog","netmon") and lbl.get("ip") in self.tor_exit:
            if lbl.get("proc","").lower() in {"notepad.exe","explorer.exe","winword.exe"}:
                incs.append({"ts": _utcnow_iso(), "severity":"medium", "title":"TOR connection by unusual process",
                             "details":{"current":ev}, "tags":["tor","anomaly"]})
        for inc in incs:
            self.c.save_incident(inc)
        return incs


def attach_siem_tab(app, tabview):
    # Reuse existing tab if present; don't add it twice.
    try:
        existing = list(getattr(tabview, "_tab_dict", {}).keys())
    except Exception:
        existing = []
    if "📈 SIEM" not in existing:
        tabview.add("📈 SIEM")
    siem_tab = tabview.tab("📈 SIEM")
    siem_tab.grid_columnconfigure(0, weight=1)
    siem_tab.grid_columnconfigure(1, weight=1)
    siem_tab.grid_rowconfigure(2, weight=1)
    siem_tab.grid_rowconfigure(3, weight=1)

    # Controls
    controls = _card(siem_tab); controls.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=12)
    for i in range(8): controls.grid_columnconfigure(i, weight=1)
    _title(controls, "SIEM/EDR-Light – Timeline & Incidents").grid(row=0, column=0, padx=12, pady=(10,4), sticky="w")
    ctk.CTkLabel(controls, text="Inputs: JSONL (logs/*.jsonl) + UDP 127.0.0.1:5140", text_color=FG_TEXT).grid(row=1, column=0, padx=12, pady=(0,8), sticky="w")

    path_var = ctk.StringVar(value=str(Path("logs").absolute()))
    ent = ctk.CTkEntry(controls, textvariable=path_var); ent.grid(row=0, column=1, padx=8, pady=(10,4), sticky="ew")
    def pick_dir():
        from tkinter import filedialog
        d = filedialog.askdirectory()
        if d: path_var.set(d)
    ctk.CTkButton(controls, text="Log folder…", command=pick_dir).grid(row=0, column=2, padx=6, pady=(10,4))
    status_lbl = ctk.CTkLabel(controls, text="Collector: stopped", text_color=FG_TEXT)
    status_lbl.grid(row=2, column=0, padx=12, pady=(0,8), sticky="w")
    start_btn = ctk.CTkButton(controls, text="Start Collector", fg_color=ACCENT, text_color="black")
    stop_btn  = ctk.CTkButton(controls, text="Stop", fg_color="#333333")
    start_btn.grid(row=0, column=3, padx=6, pady=(10,4)); stop_btn.grid(row=0, column=4, padx=6, pady=(10,4))

    tool_f = ctk.CTkEntry(controls, placeholder_text="Filter: tool"); tool_f.grid(row=1, column=1, padx=6, pady=(0,8), sticky="ew")
    level_f= ctk.CTkEntry(controls, placeholder_text="Filter: level"); level_f.grid(row=1, column=2, padx=6, pady=(0,8), sticky="ew")
    text_f = ctk.CTkEntry(controls, placeholder_text="Filter: text");  text_f.grid(row=1, column=3, padx=6, pady=(0,8), sticky="ew")
    # Quick filters
    def _only_alerts():
        level_f.delete(0, "end"); level_f.insert(0, "alert"); _append(events_box, "[ui] filter: level=alert")
    def _only_abuse():
        text_f.delete(0, "end"); text_f.insert(0, "Abuse"); _append(events_box, "[ui] filter: text=Abuse")
    def _clear_filters():
        tool_f.delete(0,"end"); level_f.delete(0,"end"); text_f.delete(0,"end"); _append(events_box, "[ui] filter: cleared")
    ctk.CTkButton(controls, text="Only Alerts", command=_only_alerts).grid(row=1, column=4, padx=6, pady=(0,8))
    ctk.CTkButton(controls, text="Only Abuse", command=_only_abuse).grid(row=1, column=5, padx=6, pady=(0,8))
    ctk.CTkButton(controls, text="Clear", command=_clear_filters).grid(row=1, column=6, padx=6, pady=(0,8))

    # Timeline
    tl = _card(siem_tab); tl.grid(row=2, column=0, sticky="nsew", padx=(12,6), pady=(0,12))
    tl.grid_columnconfigure(0, weight=1); tl.grid_rowconfigure(1, weight=1)
    ctk.CTkLabel(tl, text="Timeline", text_color=FG_TEXT).grid(row=0, column=0, padx=10, pady=(8,0), sticky="w")
    events_box = ctk.CTkTextbox(tl, height=260, corner_radius=10, fg_color=BG_DARK, text_color=FG_TEXT)
    events_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
    events_box.configure(state="disabled")

    # Incidents
    inc = _card(siem_tab); inc.grid(row=2, column=1, sticky="nsew", padx=(6,12), pady=(0,12))
    inc.grid_columnconfigure(0, weight=1); inc.grid_rowconfigure(1, weight=1)
    ctk.CTkLabel(inc, text="Incidents", text_color=FG_TEXT).grid(row=0, column=0, padx=10, pady=(8,0), sticky="w")
    incidents_box = ctk.CTkTextbox(inc, height=260, corner_radius=10, fg_color=BG_DARK, text_color=FG_TEXT)
    incidents_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
    incidents_box.configure(state="disabled")

    # Response
    resp = _card(siem_tab); resp.grid(row=3, column=0, columnspan=2, sticky="ew", padx=12, pady=(0,12))
    resp.grid_columnconfigure(4, weight=1)
    ctk.CTkLabel(resp, text="Response:", text_color=FG_TEXT).grid(row=0, column=0, padx=10, pady=10, sticky="w")
    selected_ip = ctk.StringVar(value=""); selected_proc = ctk.StringVar(value="")
    ctk.CTkEntry(resp, placeholder_text="IP from last event", textvariable=selected_ip).grid(row=0, column=1, padx=6, pady=10, sticky="ew")
    ctk.CTkEntry(resp, placeholder_text="Process from last event", textvariable=selected_proc).grid(row=0, column=2, padx=6, pady=10, sticky="ew")

    def do_block_ip():
        ip = selected_ip.get().strip()
        if not ip:
            from tkinter import messagebox
            messagebox.showinfo("Block IP", "No IP detected. Select an event with labels.ip.")
            return
        try:
            subprocess.Popen([sys.executable, "null_PortBlocker.py", ip])
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Block IP", f"Could not start PortBlocker: {e}")

    def do_kill_proc():
        try:
            subprocess.Popen([sys.executable, "null_processguard_v2.py"])
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Kill process", f"Could not start ProcessGuard: {e}")

    def do_alert_msg():
        try:
            subprocess.Popen([sys.executable, "null_messenger.py"])
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Alert", f"Could not start null_messenger: {e}")

    ctk.CTkButton(resp, text="Block IP", command=do_block_ip).grid(row=0, column=3, padx=6, pady=10)
    ctk.CTkButton(resp, text="Kill process", command=do_kill_proc).grid(row=0, column=4, padx=6, pady=10)
    ctk.CTkButton(resp, text="Send alert", command=do_alert_msg).grid(row=0, column=5, padx=6, pady=10)

    # Backend
    collector = EventCollector()
    engine = RuleEngine(collector)
    started_once = {'v': False}

    def _scan_dir_files(d):
        d = Path(d)
        files = []
        if d.exists() and d.is_dir():
            for name in ("dnswatcher","processguard","ai_watchdog","netmon","watchdog"):
                files.append(str(d / f"{name}.jsonl"))
        else:
            files = [str(Path("logs")/f) for f in ("dnswatcher.jsonl","processguard.jsonl","ai_watchdog.jsonl","netmon.jsonl","watchdog.jsonl")]
        return files

    def start():
        d = path_var.get().strip()
        files = _scan_dir_files(d)
        collector.set_files(files)
        collector.start()
        start_btn.configure(state="disabled")
        stop_btn.configure(state="normal")
        status_lbl.configure(text=f"Collector: running (UDP {collector.udp_host}:{collector.udp_port}, files={len(files)})")
        if not started_once["v"]:
            _append(events_box, f"[init] Collector started — UDP {collector.udp_host}:{collector.udp_port}, files={len(files)}")

    def stop():
        collector.stop()
        start_btn.configure(state="normal")
        stop_btn.configure(state="disabled")

    start_btn.configure(command=start)
    stop_btn.configure(command=stop, state="disabled")

    def _append(box: ctk.CTkTextbox, text: str):
        box.configure(state="normal")
        box.insert("end", text + chr(10))
        box.see("end")
        box.configure(state="disabled")

    last_ip = [""]; last_proc = [""]

    def ui_tick():
        drained = 0
        while drained < 200:
            try:
                ev = collector.q.get_nowait()
            except queue.Empty:
                break
            drained += 1
            engine.add(ev)

            if (tool_f.get() and tool_f.get().lower() not in (ev.get("tool","").lower())): 
                pass
            elif (level_f.get() and level_f.get().lower() != ev.get("level","").lower()):
                pass
            elif (text_f.get() and text_f.get().lower() not in (ev.get("msg","").lower())):
                pass
            else:
                lbl = ev.get("labels",{})
                ip  = lbl.get("ip",""); proc = lbl.get("proc",""); dom = lbl.get("domain","")
                ts = ev.get("ts","")
                try:
                    hhmmss = ts.split("T",1)[1][:8]
                except Exception:
                    hhmmss = ts
                host  = ev.get("host","") or "?"
                level = ev.get("level","info")
                tool  = ev.get("tool","?")
                msg   = ev.get("msg","")
                cdn_hosts = ("cloudflare","1e100.net","compute.amazonaws.com","cloudfront.net","akamai","edgesuite.net")
                if ("Abuse" in msg or "⚠ Abuse" in msg) and any(x in (dom or "").lower() for x in cdn_hosts):
                    msg = msg.replace("⚠ Abuse", "• Neutral").replace("Abuse", "Neutral")
                line = f"{hhmmss} [{level}] [{host}] • {tool}"
                if proc:
                    pid_str = ev.get('pid', 0) or '?'
                    line += f" (PID {pid_str})"
                if ip:  line += f" → {ip}"
                if dom: line += f" • {dom}"
                line += f" | {msg}"
                _append(events_box, line)
                if ip: last_ip[0] = ip
                if proc: last_proc[0] = proc
                if last_ip[0]: selected_ip.set(last_ip[0])
                if last_proc[0]: selected_proc.set(last_proc[0])

            incs = engine.correlate(ev)
            for inc in incs:
                iline = f"{inc['ts']} [{inc['severity'].upper()}] {inc['title']} :: tags={','.join(inc.get('tags',[]))}"
                _append(incidents_box, iline)

        siem_tab.after(500, ui_tick)

    ui_tick()

# =========================
#  APP
# =========================
_theme_setup()

app = ctk.CTk()
app.title("∅ Sentinel")
app.geometry("900x720")
app.configure(fg_color=BG_DARK)

# Tabs
tabview = ctk.CTkTabview(app, width=860, height=660)
tabview.pack(padx=14, pady=14, fill="both", expand=True)
tabview.add("🟢 Monitor")
tabview.add("💬 Messenger")
tabview.add("🔐 Crypto")
tabview.add("🕸 Network")
tabview.add("☣️ Processes")
tabview.add("🚨 Alerts")
tabview.add("📈 SIEM")

# --- Messenger Tab ---
messenger_tab = tabview.tab("💬 Messenger")
messenger_tab.grid_columnconfigure(0, weight=1)
card_msg = _card(messenger_tab)
card_msg.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_msg.grid_columnconfigure(0, weight=1)
_title(card_msg, "Start secure messenger").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_null_messenger():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_messenger.py"])).start()

_btn(card_msg, "Start ∅ null_messenger", run_null_messenger).grid(row=1, column=0, sticky="n", padx=14, pady=(0,14))

# --- Monitor Tab ---
monitor_tab = tabview.tab("🟢 Monitor")
monitor_tab.grid_columnconfigure(0, weight=1)
card_mon = _card(monitor_tab); card_mon.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_mon.grid_columnconfigure(0, weight=1)
_title(card_mon, "Live Monitoring Tools").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_dnswatch():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_dnswatcher.py"])).start()
def run_ramprotect():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_protect_ram_gui.py"])).start()

row = 1
_btn(card_mon, "Start DNS Watch", run_dnswatch).grid(row=row, column=0, sticky="n", padx=14, pady=6); row += 1
_btn(card_mon, "RAM Protector", run_ramprotect).grid(row=row, column=0, sticky="n", padx=14, pady=(0,14)); row += 1

# --- Crypto Tab ---
crypto_tab = tabview.tab("🔐 Crypto")
crypto_tab.grid_columnconfigure(0, weight=1)
card_crypto = _card(crypto_tab); card_crypto.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_crypto.grid_columnconfigure(0, weight=1)
_title(card_crypto, "Cryptographic Tools").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_crypto():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "nullcrypto_gui.py"])).start()
_btn(card_crypto, "Open ∅Crypto", run_crypto).grid(row=1, column=0, sticky="n", padx=14, pady=(0,14))

# --- Network Tab ---
network_tab = tabview.tab("🕸 Network")
network_tab.grid_columnconfigure(0, weight=1)
card_net = _card(network_tab); card_net.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_net.grid_columnconfigure(0, weight=1)
_title(card_net, "Network Tools").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_netmon():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_netmon.py"])).start()
def run_netscan():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_networkscan.py"])).start()
def run_firewall_visualizer():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_firewallvisualizer.py"])).start()
def run_file_watchdog():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_filewatchdog.py"])).start()
def run_null_scanner():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_scanner.py"])).start()

r = 1
_btn(card_net, "Start Net Monitor", run_netmon).grid(row=r, column=0, sticky="n", padx=14, pady=6); r += 1
_btn(card_net, "Run Network Scan", run_netscan).grid(row=r, column=0, sticky="n", padx=14, pady=6); r += 1
_btn(card_net, "Start Firewall Visualizer", run_firewall_visualizer).grid(row=r, column=0, sticky="n", padx=14, pady=6); r += 1
_btn(card_net, "Start File Watchdog", run_file_watchdog).grid(row=r, column=0, sticky="n", padx=14, pady=(0,14)); r += 1
_btn(card_net, "Start Null Scanner", run_null_scanner).grid(row=r, column=0, sticky="n", padx=14, pady=6); r += 1

# --- Prozesse Tab ---
process_tab = tabview.tab("☣️ Processes")
process_tab.grid_columnconfigure(0, weight=1)
card_proc = _card(process_tab); card_proc.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_proc.grid_columnconfigure(0, weight=1)
_title(card_proc, "Process Control Tools").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_portblock():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_PortBlocker.py"])).start()
def run_procguard():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_processguard_v2.py"])).start()

_btn(card_proc, "Open Port Blocker", run_portblock).grid(row=1, column=0, sticky="n", padx=14, pady=6)
_btn(card_proc, "Start Process Guard", run_procguard).grid(row=2, column=0, sticky="n", padx=14, pady=(0,14))

# --- Alarme Tab ---
alarms_tab = tabview.tab("🚨 Alerts")
alarms_tab.grid_columnconfigure(0, weight=1)
card_alarm = _card(alarms_tab); card_alarm.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_alarm.grid_columnconfigure(0, weight=1)
_title(card_alarm, "Live Alerts & AI Watchdog").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_ai_watchdog():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "null_ai_watchdog_gui.py"])).start()
def run_nullsearch():
    _t.Thread(target=lambda: subprocess.run([sys.executable, "nullsearch.py"])).start()

_btn(card_alarm, "Start ∅AI Watchdog", run_ai_watchdog).grid(row=1, column=0, sticky="n", padx=14, pady=6)
_btn(card_alarm, "Run ∅Search", run_nullsearch).grid(row=2, column=0, sticky="n", padx=14, pady=(0,14))

# --- SIEM Tab attach ---
attach_siem_tab(app, tabview)

app.mainloop()