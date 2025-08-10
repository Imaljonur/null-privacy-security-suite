# null_ai_watchdog_gui_en.py
# ∅ AI Watchdog – CustomTkinter (Nullsearch Dark/Green Style)
# Standalone file. Some features require Windows + Administrator privileges.

import os, sys, re, json, time, threading, glob, platform, subprocess, ctypes, socket
from functools import lru_cache

# Third-party
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import psutil
import requests
try:
    from PIL import Image, ImageDraw
except Exception:
    Image = ImageDraw = None
try:
    import pystray
except Exception:
    pystray = None

# Optional: Crypto Buttons (if your module exists)
try:
    from nullcrypto_gui import encrypt_data, decrypt_data
except Exception:
    encrypt_data = decrypt_data = None

# Optional: ML
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_OK = True
except Exception:
    SKLEARN_OK = False

# ======== Theme ========
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

ACCENT        = "#00FF88"
BG_DARK       = "#0B0F10"
BG_CARD       = "#12171A"
FG_TEXT       = "#D7E0E6"
FG_MUTED      = "#8FA3AD"
FG_OK         = "#7CE38B"
FG_BAD        = "#FF0000"
FG_WARN       = "#FFD500"
BORDER        = "#1D252B"

IS_WIN = platform.system().lower().startswith("win")
APP_CONFIG_FILE = "honeytokens_config.json"
MODEL_FILE = "watchdog_model.pkl"

# ======== Admin Elevation (Windows) ========
def is_admin():
    if not IS_WIN:
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def ensure_admin_windows():
    if not IS_WIN:
        return
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
    except Exception:
        pass

if IS_WIN:
    ensure_admin_windows()

# ======== Config ========
def default_config():
    user_docs = os.path.expanduser("~/Documents")
    return {
        "auto_create_on_start": True,
        "enable_txt": True,
        "txt_path": os.path.join(user_docs, "passwords_backup.txt"),
        "enable_dll_trap": True,
        "dll_trap_path": os.path.expanduser("~\\AppData\\Local\\Temp\\keyboardhook.dll"),
        "enable_pdfs": True,
        "pdfs": [
            os.path.join(user_docs, "TaxNotice2024.pdf"),
            os.path.join(user_docs, "Crypto_Payout_Receipt.pdf")
        ],
        "enable_btc_wallet": True,
        "btc_wallet_path": os.path.expanduser("~\\AppData\\Roaming\\Electrum\\wallets\\honeywallet.dat"),
        "enable_registry_honeykey": True,
        "registry_key_path": r"Software\\WinCache\\Creds",
        "registry_values": {"AdminPass": "SuperSecurePassword123!#honey"},
        "enable_fake_wifi_profiles": True,
        "wifi_profiles": [
            {"ssid": "Company-Internal", "key": "Wi!SPKDJn+pswdu"},
            {"ssid": "SavingsBank-IT", "key": "fP9S^d33wWq!"},
            {"ssid": "VPN-Gateway", "key": "u#PPa43pKle2"},
            {"ssid": "Admin-Zone", "key": "RootAccess!"}
        ],
        "wifi_profiles_path": os.path.expanduser("~\\AppData\\Microsoft\\Windows\\WCN\\wcnprofiles.xml"),
    }

def load_config():
    if os.path.exists(APP_CONFIG_FILE):
        try:
            with open(APP_CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    cfg = default_config()
    save_config(cfg)
    return cfg

def save_config(cfg):
    try:
        with open(APP_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

CONFIG = load_config()

# ======== Whitelist ========
def load_whitelist():
    processes = set()
    paths = set()
    if os.path.exists("whitelist.txt"):
        with open("whitelist.txt", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip().lower()
                if line.startswith("proc:"):
                    processes.add(line.replace("proc:", "").strip())
                elif line.startswith("path:"):
                    paths.add(line.replace("path:", "").strip())
    return processes, paths

whitelisted_processes, whitelisted_paths = load_whitelist()

# ======== Honeytokens ========
def _create_txt_honeytoken(path: str, log_fn):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write("[Credentials]\nAdmin: BlinkiFunki23\nRoot: ÜAIOPsj0p98ujA\n\nMasterPassword: *'SAÜPOduj0´98ujüäp0>ISAjd\n")
            log_fn(f"📄 TXT honeytoken created: {path}", "blue")
        else:
            log_fn(f"📄 TXT honeytoken already present: {path}", "gray")
    except Exception as e:
        log_fn(f"❌ Error creating TXT honeytoken: {e}", "gray")

def create_dll_trap(path: str, log_fn):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(b"Fake DLL - Trap for malware.")
            log_fn(f"🧲 DLL trap file created: {path}", "blue")
        else:
            log_fn(f"🧲 DLL trap file already present: {path}", "gray")
    except Exception as e:
        log_fn(f"❌ Error creating DLL trap: {e}", "gray")

def ensure_all_honeytokens(cfg, log_fn):
    if cfg.get("enable_txt"):
        _create_txt_honeytoken(cfg.get("txt_path"), log_fn)
    if cfg.get("enable_dll_trap"):
        create_dll_trap(cfg.get("dll_trap_path"), log_fn)
    if cfg.get("enable_pdfs"):
        try:
            for pdf in cfg.get("pdfs", []):
                os.makedirs(os.path.dirname(pdf), exist_ok=True)
                if not os.path.exists(pdf):
                    with open(pdf, "wb") as f:
                        f.write(b"%PDF-1.4\n%Fake Tax Notice honeytoken\n")
                    log_fn(f"📄 Fake PDF honeytoken created: {pdf}", "blue")
                else:
                    log_fn(f"📄 Fake PDF honeytoken already present: {pdf}", "gray")
        except Exception as e:
            log_fn(f"❌ Error creating PDF honeytoken: {e}", "gray")
    if cfg.get("enable_btc_wallet"):
        btc_path = cfg.get("btc_wallet_path")
        try:
            os.makedirs(os.path.dirname(btc_path), exist_ok=True)
            if not os.path.exists(btc_path):
                with open(btc_path, "w", encoding="utf-8") as f:
                    f.write("fake btc wallet backup\nPrivateKey: 5J...FakeKey...honeytrap")
                log_fn(f"🪙 BTC honeytoken created: {btc_path}", "blue")
            else:
                log_fn(f"🪙 BTC honeytoken already present: {btc_path}", "gray")
        except Exception as e:
            log_fn(f"❌ Error creating BTC wallet honeytoken: {e}", "gray")
    if cfg.get("enable_fake_wifi_profiles"):
        try:
            fake_path = cfg.get("wifi_profiles_path")
            os.makedirs(os.path.dirname(fake_path), exist_ok=True)
            xml_lines = ["<Profiles>"]
            for prof in cfg.get("wifi_profiles", []):
                xml_lines.extend([
                    "  <Profile>",
                    f"    <SSID>{prof.get('ssid','')}</SSID>",
                    f"    <Key>{prof.get('key','')}</Key>",
                    "  </Profile>"
                ])
            xml_lines.append("</Profiles>")
            with open(fake_path, "w", encoding="utf-8") as f:
                f.write("\n".join(xml_lines))
            log_fn(f"🛰️ Fake Wi‑Fi profiles (WCN XML) created: {', '.join([p.get('ssid','') for p in cfg.get('wifi_profiles',[])])}", "blue")
        except Exception as e:
            log_fn(f"❌ Error creating fake Wi‑Fi profiles: {e}", "red")

# ======== ttk style ========
def style_treeview():
    style = ttk.Style()
    try:
        style.theme_use("default")
    except Exception:
        pass
    style.configure("Treeview",
                    background=BG_CARD,
                    fieldbackground=BG_CARD,
                    foreground=FG_TEXT,
                    bordercolor=BORDER,
                    rowheight=26)
    style.configure("Treeview.Heading",
                    background=BG_CARD,
                    foreground=FG_MUTED)
    style.map("Treeview", background=[("selected", "#23313A")])

# ======== App ========
class AIWatchdogApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("∅ AI Watchdog")
        self.geometry("1200x780")
        self.configure(fg_color=BG_DARK)

        # State
        self.is_monitoring = ctk.BooleanVar(value=False)
        self.start_time = time.time()
        self.monitor_threads = []
        self.counters = {"events":0, "warn":0, "honey":0, "anom":0}

        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._build_statusbar()
        style_treeview()

        # auto honeytokens
        if CONFIG.get("auto_create_on_start", True):
            self.log("Auto: creating honeytokens …", FG_MUTED)
            ensure_all_honeytokens(CONFIG, self._log_color)
        else:
            self.log("ℹ Auto-creation of honeytokens is off.", FG_WARN)

        # Dummy events
        self._emit_dummy_events()

        # clock
        self.after(250, self._tick)

    # ---------- UI ----------
    def _card(self, parent):
        return ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=14, border_color=BORDER, border_width=1)

    def _build_sidebar(self):
        self.sidebar = self._card(self)
        self.sidebar.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        self.sidebar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.sidebar, text="∅ AI Watchdog", text_color=ACCENT,
                     font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        ctk.CTkLabel(self.sidebar, text="Monitoring & Honeytokens", text_color=FG_MUTED)\
            .grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

        self.btn_start = ctk.CTkButton(self.sidebar, text="▶ Start", fg_color=ACCENT, text_color="black", command=self.start_monitoring)
        self.btn_start.grid(row=2, column=0, padx=16, pady=(0,8), sticky="ew")
        self.btn_stop  = ctk.CTkButton(self.sidebar, text="⏸ Stop", fg_color="#1F2933", hover_color="#25313B", command=self.stop_monitoring)
        self.btn_stop.grid(row=3, column=0, padx=16, pady=(0,16), sticky="ew")

        self.btn_honey = ctk.CTkButton(self.sidebar, text="Honeytoken Manager", command=self.open_honeytoken_manager,
                                       fg_color="#1F2933", hover_color="#25313B")
        self.btn_honey.grid(row=4, column=0, padx=16, pady=(0,12), sticky="ew")

        scans = self._card(self.sidebar)
        scans.grid(row=5, column=0, padx=16, pady=(0,12), sticky="ew")
        ctk.CTkLabel(scans, text="Scans & Learning", text_color=FG_MUTED).pack(anchor="w", padx=10, pady=(8,2))
        self.learn_dropdown = ctk.CTkComboBox(scans, values=["5 minutes","10 minutes","30 minutes","60 minutes"])
        self.learn_dropdown.set("10 minutes")
        self.learn_dropdown.pack(fill="x", padx=10, pady=(4,4))
        ctk.CTkButton(scans, text="Start Auto‑Learn", command=self.start_auto_learn,
                      fg_color="#1F2933", hover_color="#25313B").pack(fill="x", padx=10, pady=(0,6))
        ctk.CTkButton(scans, text="USB Scan now", command=self.manual_usb_scan,
                      fg_color="#1F2933", hover_color="#25313B").pack(fill="x", padx=10, pady=(0,10))

        proc = self._card(self.sidebar)
        proc.grid(row=6, column=0, padx=16, pady=(0,12), sticky="ew")
        ctk.CTkLabel(proc, text="Process control", text_color=FG_MUTED).pack(anchor="w", padx=10, pady=(8,2))
        ctk.CTkButton(proc, text="🔴 Kill ALL (from selection)", command=self.kill_selected_all,
                      fg_color="#B84C4C", hover_color="#A03E3E").pack(fill="x", padx=10, pady=(0,6))
        ctk.CTkButton(proc, text="Kill ONE (from selection)", command=self.kill_selected_one,
                      fg_color="#1F2933", hover_color="#25313B").pack(fill="x", padx=10, pady=(0,10))

        fw = self._card(self.sidebar)
        fw.grid(row=7, column=0, padx=16, pady=(0,12), sticky="ew")
        ctk.CTkLabel(fw, text="Firewall IP block/unblock", text_color=FG_MUTED).pack(anchor="w", padx=10, pady=(8,2))
        self.ip_var = ctk.StringVar()
        ctk.CTkEntry(fw, textvariable=self.ip_var, placeholder_text="IP address …").pack(fill="x", padx=10, pady=(2,6))
        ctk.CTkButton(fw, text="Block", command=self.manual_block_ip,
                      fg_color="#1F2933", hover_color="#25313B").pack(fill="x", padx=10, pady=(0,4))
        ctk.CTkButton(fw, text="Unblock", command=self.manual_unblock_ip,
                      fg_color="#1F2933", hover_color="#25313B").pack(fill="x", padx=10, pady=(0,10))

        misc = self._card(self.sidebar)
        misc.grid(row=8, column=0, padx=16, pady=(0,12), sticky="ew")
        ctk.CTkLabel(misc, text="Misc", text_color=FG_MUTED).pack(anchor="w", padx=10, pady=(8,2))
        ctk.CTkButton(misc, text="Whitelist Editor", command=self.open_whitelist_editor,
                      fg_color="#1F2933", hover_color="#25313B").pack(fill="x", padx=10, pady=(0,6))
        if encrypt_data and decrypt_data:
            ctk.CTkButton(misc, text="Encrypt all & exit", command=self.encrypt_and_quit,
                          fg_color="#1F2933", hover_color="#25313B").pack(fill="x", padx=10, pady=(0,6))
            ctk.CTkButton(misc, text="Decrypt & reload", command=self.decrypt_and_reload,
                          fg_color="#1F2933", hover_color="#25313B").pack(fill="x", padx=10, pady=(0,10))

        ctk.CTkLabel(self.sidebar, text="Note: Some features require administrator rights.",
                     text_color=FG_MUTED, font=ctk.CTkFont(size=12), wraplength=230).grid(row=9, column=0, padx=16, pady=(0,10), sticky="w")

    def _build_main(self):
        self.main = self._card(self)
        self.main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self.main, fg_color=BG_CARD)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
        header.grid_columnconfigure(0, weight=1)
        self.state_label = ctk.CTkLabel(header, text="Status: idle", text_color=FG_MUTED)
        self.state_label.grid(row=0, column=0, sticky="w")
        self.time_label = ctk.CTkLabel(header, text="", text_color=FG_MUTED)
        self.time_label.grid(row=0, column=1, sticky="e")

        body = ctk.CTkFrame(self.main, fg_color=BG_CARD)
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self.log_box = ctk.CTkTextbox(body, width=940, height=560)
        self.log_box.grid(row=0, column=0, sticky="nsew")
        vsb = ctk.CTkScrollbar(body, command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=vsb.set)
        vsb.grid(row=0, column=1, sticky="ns")

    def _build_statusbar(self):
        self.status = self._card(self)
        self.status.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
        self.status.grid_columnconfigure((0,1,2,3,4), weight=1)

        def metric(label, value):
            box = ctk.CTkFrame(self.status, fg_color=BG_CARD)
            title = ctk.CTkLabel(box, text=label, text_color=FG_MUTED, font=ctk.CTkFont(size=12))
            val   = ctk.CTkLabel(box, text=value, text_color=ACCENT, font=ctk.CTkFont(size=18, weight="bold"))
            title.pack(anchor="center", pady=(8,0))
            val.pack(anchor="center", pady=(0,8))
            return box, val

        self.box_events, self.lbl_events = metric("Events", "0")
        self.box_warn,   self.lbl_warn   = metric("Warnings", "0")
        self.box_honey,  self.lbl_honey  = metric("Honeytoken Alerts", "0")
        self.box_anom,   self.lbl_anom   = metric("AI Anomalies", "0")
        self.box_state,  self.lbl_state  = metric("State", "idle")

        self.box_events.grid(row=0, column=0, sticky="ew", padx=(0,8))
        self.box_warn.grid(row=0, column=1, sticky="ew", padx=8)
        self.box_honey.grid(row=0, column=2, sticky="ew", padx=8)
        self.box_anom.grid(row=0, column=3, sticky="ew", padx=8)
        self.box_state.grid(row=0, column=4, sticky="ew", padx=(8,0))

    # ---------- Logging ----------
    def _log_color(self, text, color_hex):
        tag = color_hex
        try:
            self.log_box.insert("end", f"{time.strftime('%H:%M:%S')}  |  {text}\n", (tag,))
            self.log_box.tag_config(tag, foreground=color_hex)
            self.log_box.see("end")
        except Exception:
            pass
        try:
            with open("watchdog.log", "a", encoding="utf-8") as logfile:
                logfile.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {text}\n")
        except Exception:
            pass
        # counters
        self.counters["events"] += 1
        if "⚠" in text or "error" in text.lower():
            self.counters["warn"] += 1
            self.lbl_warn.configure(text=str(self.counters["warn"]))
        if "Honeytoken" in text or "honeytoken" in text:
            self.counters["honey"] += 1
            self.lbl_honey.configure(text=str(self.counters["honey"]))
        if "AI:" in text or "Anomal" in text or "anomal" in text:
            self.counters["anom"] += 1
            self.lbl_anom.configure(text=str(self.counters["anom"]))
        self.lbl_events.configure(text=str(self.counters["events"]))

    def log(self, text, color=FG_OK):
        self._log_color(text, color)

    # ---------- Actions ----------
    def start_monitoring(self):
        if self.is_monitoring.get():
            return
        self.is_monitoring.set(True)
        self._set_state("running")
        self.log("Monitoring started.", ACCENT)
        self.monitor_threads = [
            threading.Thread(target=self.ai_watchdog_loop, daemon=True),
            threading.Thread(target=self.scan_loaded_dlls, daemon=True),
            threading.Thread(target=self.detect_keyloggers, daemon=True),
            threading.Thread(target=self.scan_keylog_files, daemon=True),
            threading.Thread(target=self.scan_keylogger_autostarts, daemon=True),
            threading.Thread(target=self.refresh_tor_ips_periodically, daemon=True),
            threading.Thread(target=self.detect_tor_traffic, daemon=True),
            threading.Thread(target=self.monitor_honeytoken, daemon=True),
            threading.Thread(target=self.check_dns_leaks, daemon=True),
        ]
        for t in self.monitor_threads:
            t.start()

    def stop_monitoring(self):
        if not self.is_monitoring.get():
            return
        self.is_monitoring.set(False)
        self._set_state("stopped")
        self.log("Monitoring stopped.", FG_BAD)

    # ---- subdialogs ----
    def open_honeytoken_manager(self):
        cfg = load_config()
        win = ctk.CTkToplevel(self)
        win.title("Honeytoken Manager")
        win.geometry("860x680")

        auto_var = ctk.BooleanVar(value=cfg.get("auto_create_on_start", True))
        ctk.CTkCheckBox(win, text="Create automatically on startup", variable=auto_var).pack(anchor="w", padx=10, pady=(10,4))

        # TXT
        frame_txt = ctk.CTkFrame(win)
        frame_txt.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(frame_txt, text="TXT Honeytoken").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        txt_enable = ctk.BooleanVar(value=cfg.get("enable_txt", True))
        ctk.CTkCheckBox(frame_txt, text="enabled", variable=txt_enable).grid(row=0, column=1, padx=8)
        txt_entry = ctk.CTkEntry(frame_txt, width=600)
        txt_entry.insert(0, cfg.get("txt_path",""))
        txt_entry.grid(row=1, column=0, columnspan=3, padx=8, pady=(0,8), sticky="w")

        # DLL Trap
        frame_dll = ctk.CTkFrame(win)
        frame_dll.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(frame_dll, text="DLL Trap").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        dll_enable = ctk.BooleanVar(value=cfg.get("enable_dll_trap", True))
        ctk.CTkCheckBox(frame_dll, text="enabled", variable=dll_enable).grid(row=0, column=1, padx=8)
        dll_entry = ctk.CTkEntry(frame_dll, width=600)
        dll_entry.insert(0, cfg.get("dll_trap_path",""))
        dll_entry.grid(row=1, column=0, columnspan=3, padx=8, pady=(0,8), sticky="w")

        # PDFs
        frame_pdf = ctk.CTkFrame(win)
        frame_pdf.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(frame_pdf, text="PDF Honeytokens (list)").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        pdf_enable = ctk.BooleanVar(value=cfg.get("enable_pdfs", True))
        ctk.CTkCheckBox(frame_pdf, text="enabled", variable=pdf_enable).grid(row=0, column=1, padx=8)
        pdf_list = ctk.CTkTextbox(frame_pdf, width=640, height=120)
        pdf_list.grid(row=1, column=0, columnspan=3, padx=8, pady=(0,8), sticky="w")
        for p in cfg.get("pdfs", []):
            pdf_list.insert("end", p + "\n")
        def add_pdf():
            p = ctk.CTkInputDialog(text="Path/name of the PDF:", title="Add PDF").get_input()
            if p:
                pdf_list.insert("end", p + "\n")
        def remove_pdf():
            try:
                sel_start = pdf_list.index("sel.first linestart")
                sel_end = pdf_list.index("sel.last lineend")
                pdf_list.delete(sel_start, sel_end)
            except Exception:
                self.log("⚠️ Nothing selected to remove.", FG_WARN)
        ctk.CTkButton(frame_pdf, text="Add", command=add_pdf).grid(row=2, column=0, padx=8, pady=4, sticky="w")
        ctk.CTkButton(frame_pdf, text="Remove selection", command=remove_pdf).grid(row=2, column=1, padx=8, pady=4, sticky="w")

        # BTC
        frame_btc = ctk.CTkFrame(win)
        frame_btc.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(frame_btc, text="BTC Wallet Honeytoken").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        btc_enable = ctk.BooleanVar(value=cfg.get("enable_btc_wallet", True))
        ctk.CTkCheckBox(frame_btc, text="enabled", variable=btc_enable).grid(row=0, column=1, padx=8)
        btc_entry = ctk.CTkEntry(frame_btc, width=600)
        btc_entry.insert(0, cfg.get("btc_wallet_path",""))
        btc_entry.grid(row=1, column=0, columnspan=3, padx=8, pady=(0,8), sticky="w")

        # Registry
        frame_reg = ctk.CTkFrame(win)
        frame_reg.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(frame_reg, text="Registry honeykey (Windows only)").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        reg_enable = ctk.BooleanVar(value=cfg.get("enable_registry_honeykey", True))
        ctk.CTkCheckBox(frame_reg, text="enabled", variable=reg_enable).grid(row=0, column=1, padx=8)
        reg_path_entry = ctk.CTkEntry(frame_reg, width=600)
        reg_path_entry.insert(0, cfg.get("registry_key_path", r"Software\\WinCache\\Creds"))
        reg_path_entry.grid(row=1, column=0, columnspan=3, padx=8, pady=(0,8), sticky="w")
        adminpass_entry = ctk.CTkEntry(frame_reg, width=600, placeholder_text="AdminPass value")
        adminpass_entry.insert(0, cfg.get("registry_values",{}).get("AdminPass",""))
        adminpass_entry.grid(row=2, column=0, columnspan=3, padx=8, pady=(0,8), sticky="w")

        # Fake WiFi
        frame_wifi = ctk.CTkFrame(win)
        frame_wifi.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(frame_wifi, text="Fake Wi‑Fi profiles").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        wifi_enable = ctk.BooleanVar(value=cfg.get("enable_fake_wifi_profiles", True))
        ctk.CTkCheckBox(frame_wifi, text="enabled", variable=wifi_enable).grid(row=0, column=1, padx=8)
        wifi_path_entry = ctk.CTkEntry(frame_wifi, width=600, placeholder_text="Path to wcnprofiles.xml")
        wifi_path_entry.insert(0, cfg.get("wifi_profiles_path",""))
        wifi_path_entry.grid(row=1, column=0, columnspan=3, padx=8, pady=(0,8), sticky="w")

        wifi_list = ctk.CTkTextbox(frame_wifi, width=640, height=120)
        wifi_list.grid(row=2, column=0, columnspan=3, padx=8, pady=(0,8), sticky="w")
        for p in cfg.get("wifi_profiles", []):
            wifi_list.insert("end", f"{p.get('ssid','')},{p.get('key','')}\n")
        def add_wifi():
            ssid = ctk.CTkInputDialog(text="SSID:", title="Add Wi‑Fi").get_input()
            if not ssid: return
            key = ctk.CTkInputDialog(text="Key:", title="Add Wi‑Fi").get_input()
            if key is None: key = ""
            wifi_list.insert("end", f"{ssid},{key}\n")
        def remove_wifi():
            try:
                sel_start = wifi_list.index("sel.first linestart")
                sel_end = wifi_list.index("sel.last lineend")
                wifi_list.delete(sel_start, sel_end)
            except Exception:
                self.log("⚠️ No Wi‑Fi selected.", FG_WARN)
        ctk.CTkButton(frame_wifi, text="Add", command=add_wifi).grid(row=3, column=0, padx=8, pady=4, sticky="w")
        ctk.CTkButton(frame_wifi, text="Remove selection", command=remove_wifi).grid(row=3, column=1, padx=8, pady=4, sticky="w")

        button_bar = ctk.CTkFrame(win)
        button_bar.pack(fill="x", padx=10, pady=10)
        def do_save():
            new_cfg = {
                "auto_create_on_start": bool(auto_var.get()),
                "enable_txt": bool(txt_enable.get()),
                "txt_path": txt_entry.get().strip(),
                "enable_dll_trap": bool(dll_enable.get()),
                "dll_trap_path": dll_entry.get().strip(),
                "enable_pdfs": bool(pdf_enable.get()),
                "pdfs": [line.strip() for line in pdf_list.get("1.0","end").splitlines() if line.strip()],
                "enable_btc_wallet": bool(btc_enable.get()),
                "btc_wallet_path": btc_entry.get().strip(),
                "enable_registry_honeykey": bool(reg_enable.get()),
                "registry_key_path": reg_path_entry.get().strip() or r"Software\\WinCache\\Creds",
                "registry_values": {"AdminPass": adminpass_entry.get().strip()},
                "enable_fake_wifi_profiles": bool(wifi_enable.get()),
                "wifi_profiles_path": wifi_path_entry.get().strip(),
                "wifi_profiles": []
            }
            for line in wifi_list.get("1.0","end").splitlines():
                line = line.strip()
                if not line: continue
                if "," in line:
                    ssid, key = line.split(",", 1)
                else:
                    ssid, key = line, ""
                new_cfg["wifi_profiles"].append({"ssid": ssid.strip(), "key": key.strip()})
            save_config(new_cfg)
            global CONFIG
            CONFIG = new_cfg
            self.log("✅ Settings saved.", ACCENT)
        def do_create_now():
            do_save()
            ensure_all_honeytokens(CONFIG, self._log_color)
        ctk.CTkButton(button_bar, text="Save", command=do_save).pack(side="left", padx=6)
        ctk.CTkButton(button_bar, text="Create now", command=do_create_now).pack(side="left", padx=6)

    def open_whitelist_editor(self):
        editor = ctk.CTkToplevel(self)
        editor.title("Whitelist Editor")
        editor.geometry("520x420")
        listbox = ctk.CTkTextbox(editor, width=480, height=260)
        listbox.pack(padx=10, pady=10)
        entries = []
        if os.path.exists("whitelist.txt"):
            with open("whitelist.txt", "r", encoding="utf-8", errors="ignore") as f:
                entries = [line.strip() for line in f if line.strip()]
        for e in entries:
            listbox.insert("end", e + "\n")
        entry_var = ctk.StringVar()
        entry_box = ctk.CTkEntry(editor, width=400, textvariable=entry_var, placeholder_text="proc:example.exe or path:C:/Programs/Test/")
        entry_box.pack(padx=10, pady=5)
        def add_entry():
            entry = entry_var.get().strip().lower()
            if entry and (entry.startswith("proc:") or entry.startswith("path:")) and entry not in entries:
                entries.append(entry)
                listbox.insert("end", entry + "\n")
                entry_var.set("")
            else:
                self.log("⚠️ Invalid or duplicate whitelist entry", FG_WARN)
        def remove_selected():
            try:
                sel_start = listbox.index("sel.first linestart")
                sel_end = listbox.index("sel.last lineend")
                selected = listbox.get(sel_start, sel_end).strip()
                if selected in entries:
                    entries.remove(selected)
                    listbox.delete(sel_start, sel_end)
            except Exception:
                self.log("⚠️ Nothing selected or error removing", FG_WARN)
        ctk.CTkButton(editor, text="Add", command=add_entry).pack(pady=2)
        ctk.CTkButton(editor, text="Remove selection", command=remove_selected).pack(pady=2)
        def save_and_close():
            with open("whitelist.txt", "w", encoding="utf-8") as f:
                for e in entries:
                    f.write(e + "\n")
            global whitelisted_processes, whitelisted_paths
            whitelisted_processes, whitelisted_paths = load_whitelist()
            self.log("✅ Whitelist saved & reloaded.", ACCENT)
            editor.destroy()
        ctk.CTkButton(editor, text="Save & Close", command=save_and_close).pack(pady=5)

    def manual_usb_scan(self):
        try:
            # Minimal scan; detailed WMI scan optional
            for p in psutil.disk_partitions(all=False):
                if "removable" in (p.opts or "").lower():
                    self.log(f"⚠️ USB device detected: {p.device}", FG_WARN)
            if pystray is None:
                self.log("ℹ️ Tray icon is not available (pystray missing).", FG_MUTED)
        except Exception as e:
            self.log(f"❌ USB scan error: {e}", FG_BAD)

    def start_auto_learn(self):
        if not SKLEARN_OK:
            self.log("❌ sklearn is not installed – Auto‑Learn disabled.", FG_BAD)
            return
        label = self.learn_dropdown.get()
        mapping = {"5 minutes":300, "10 minutes":600, "30 minutes":1800, "60 minutes":3600}
        duration = mapping.get(label, 600)
        threading.Thread(target=self._auto_learn_worker, args=(duration,), daemon=True).start()

    def _auto_learn_worker(self, duration_sec):
        self.log(f"🧠 Auto‑Learn started ({duration_sec//60} minutes) …", ACCENT)
        data = []
        start = time.time()
        while time.time() - start < duration_sec:
            for conn in psutil.net_connections(kind='inet'):
                ip = conn.raddr.ip if conn.raddr else None
                pid = conn.pid
                if ip and pid:
                    abroad = 0
                    try:
                        geo = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=2).json()
                        abroad = 0 if geo.get("countryCode") in ("DE","AT","CH") else 1
                    except Exception:
                        pass
                    hour = time.localtime().tm_hour
                    try:
                        cpu = psutil.Process(pid).cpu_percent(interval=0.05)
                    except Exception:
                        cpu = 0.0
                    data.append([pid % 1000, abroad, hour, cpu])
            time.sleep(1.2)
        try:
            clf = IsolationForest(contamination=0.01)
            clf.fit(data)
            import pickle
            with open(MODEL_FILE, "wb") as f:
                pickle.dump(clf, f)
            self.log("✅ Auto‑Learn finished & model saved.", ACCENT)
        except Exception as e:
            self.log(f"❌ Auto‑Learn error: {e}", FG_BAD)

    def manual_block_ip(self):
        ip = (self.ip_var.get() or "").strip()
        if not ip:
            self.log("⚠️ No IP provided!", FG_WARN)
            return
        if not IS_WIN:
            self.log("❌ Firewall block only on Windows (netsh).", FG_BAD)
            return
        try:
            rule_name = f"AIWatchdog_Block_{ip}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip} enable=yes'
            subprocess.run(cmd, shell=True, check=True)
            self.log(f"🔥 Firewall: IP blocked {ip}", FG_BAD)
        except Exception as e:
            self.log(f"❌ Firewall block error: {e}", FG_BAD)

    def manual_unblock_ip(self):
        ip = (self.ip_var.get() or "").strip()
        if not ip:
            self.log("⚠️ No IP provided!", FG_WARN)
            return
        if not IS_WIN:
            self.log("❌ Unblock only on Windows (netsh).", FG_BAD)
            return
        try:
            rule_name = f"AIWatchdog_Block_{ip}"
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(cmd, shell=True, check=True)
            self.log(f"✅ Firewall: IP unblocked {ip}", ACCENT)
        except Exception as e:
            self.log(f"❌ Unblock error: {e}", FG_BAD)

    def kill_selected_all(self):
        pname, _ = self._parse_selected_name_and_pid()
        if not pname:
            self.log("❌ No valid selection (process name).", FG_BAD)
            return
        killed = 0
        for proc in psutil.process_iter(['pid','name']):
            try:
                if proc.info['name'].lower() == pname.lower():
                    psutil.Process(proc.info['pid']).kill()
                    killed += 1
            except Exception:
                continue
        if killed:
            self.log(f"🔥 ALL processes named {pname} terminated ({killed})", FG_BAD)
        else:
            self.log(f"⚠️ No processes named {pname} found", FG_WARN)

    def kill_selected_one(self):
        pname, pid = self._parse_selected_name_and_pid()
        if pid:
            try:
                psutil.Process(pid).kill()
                self.log(f"✅ Process with PID {pid} terminated.", ACCENT)
            except Exception as e:
                self.log(f"❌ Error terminating PID {pid}: {e}", FG_BAD)
        elif pname:
            for proc in psutil.process_iter(['pid','name']):
                if proc.info['name'].lower() == pname.lower():
                    try:
                        psutil.Process(proc.info['pid']).kill()
                        self.log(f"✅ {pname} (PID {proc.info['pid']}) terminated.", ACCENT)
                        return
                    except Exception as e:
                        self.log(f"❌ Error: {e}", FG_BAD)
            self.log(f"⚠️ No instance of {pname} found.", FG_WARN)
        else:
            self.log("❌ No valid selection (PID/name).", FG_BAD)

    def _parse_selected_name_and_pid(self):
        try:
            selected_text = self.log_box.get("sel.first", "sel.last")
        except Exception:
            selected_text = ""
        pname = None
        pid = None
        m = re.search(r'([A-Za-z0-9_.-]+)\s*\(PID\s*(\d+)\)', selected_text)
        if m:
            pname = m.group(1)
            pid = int(m.group(2))
        else:
            if "PID" in selected_text:
                try:
                    pname = selected_text.split(" (PID")[0].split("|")[-1].strip()
                except Exception:
                    pname = None
            m2 = re.search(r'\bPID\s*(\d+)\b', selected_text)
            if m2:
                pid = int(m2.group(1))
        return pname, pid

    # ---------- Monitoring Loops ----------
    def ai_watchdog_loop(self):
        unusual_procs = {"notepad.exe","wordpad.exe","explorer.exe","winword.exe","excel.exe","calc.exe"}
        while self.is_monitoring.get():
            try:
                for conn in psutil.net_connections(kind='inet'):
                    ip = conn.raddr.ip if conn.raddr else None
                    pid = conn.pid
                    if not ip or not pid:
                        continue
                    try:
                        pname = psutil.Process(pid).name()
                    except Exception:
                        pname = "Unknown"
                    country, abuse = self.get_ip_info(ip)
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = "Unknown"
                    if pname.lower() in unusual_procs and all(cc not in country for cc in ("DE","AT","CH")):
                        self._log_color(f"⚠️ Unusual network activity: {pname} (PID {pid}) → {ip} ({country})", FG_WARN)
                    self.log(f"{pname} (PID {pid}) → {ip} ({hostname}) | {country} | {abuse}", FG_OK)
            except Exception as e:
                self.log(f"❌ Watchdog loop error: {e}", FG_BAD)
            time.sleep(4)

    def get_ip_info(self, ip):
        try:
            geo = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,country,proxy,hosting", timeout=3).json()
            country = f"{geo.get('country','Unknown')} ({geo.get('countryCode','XX')})"
            abuse = "⚠ Abuse" if (geo.get('proxy') or geo.get('hosting')) else "✓ Clean"
        except Exception:
            country = "Unknown (XX)"
            abuse = "✓ Clean"
        return country, abuse

    def scan_loaded_dlls(self):
        suspicious_markers = ['keylog', 'hook', 'inject', 'spy']
        dll_trap = (CONFIG.get("dll_trap_path","") or "").lower()
        while self.is_monitoring.get():
            try:
                for p in psutil.process_iter(['pid','name']):
                    try:
                        proc = psutil.Process(p.pid)
                        for mm in proc.memory_maps():
                            path = (mm.path or "").lower()
                            if not path:
                                continue
                            if dll_trap and dll_trap in path:
                                self._log_color(f"⚠️ DLL trap opened by {proc.name()} (PID {p.pid})", FG_BAD)
                            elif any(s in path for s in suspicious_markers):
                                if proc.name().lower() in whitelisted_processes or self._is_whitelisted_path(path):
                                    self._log_color(f"ℹ️ Whitelisted DLL: {path} (PID {p.pid})", FG_MUTED)
                                else:
                                    self._log_color(f"⚠️ Suspicious DLL: {path} (PID {p.pid})", FG_WARN)
                    except Exception:
                        continue
            except Exception:
                pass
            time.sleep(20)

    def _is_whitelisted_path(self, path):
        norm = os.path.normcase(os.path.normpath(path)).replace("\\","/")
        for wp in whitelisted_paths:
            nwp = os.path.normcase(os.path.normpath(wp)).replace("\\","/")
            if norm.startswith(nwp):
                return True
        return False

    def detect_keyloggers(self):
        while self.is_monitoring.get():
            try:
                for proc in psutil.process_iter(['pid','name','cmdline']):
                    name = (proc.info['name'] or "").lower()
                    cmd = " ".join(proc.info.get('cmdline') or []).lower()
                    if any(k in name+cmd for k in ["keylog","keystroke","hook","spy"]):
                        self._log_color(f"⚠️ Keylogger heuristic: {proc.info['name']} (PID {proc.info['pid']})", FG_WARN)
            except Exception:
                pass
            time.sleep(30)

    def scan_keylog_files(self):
        suspicious_names = ["keylog.txt","logger.txt","keystrokes.txt","kl_data.log","record.txt","captured_keys.txt"]
        userdirs = [os.environ.get('APPDATA',''), os.environ.get('LOCALAPPDATA',''),
                    os.environ.get('TEMP',''), os.environ.get('USERPROFILE',''), os.environ.get('PROGRAMDATA','')]
        while self.is_monitoring.get():
            try:
                for d in userdirs:
                    if not d: continue
                    for name in suspicious_names:
                        for f in glob.glob(os.path.join(d, "**", name), recursive=True):
                            self._log_color(f"⚠️ Suspicious keylogger file found: {f}", FG_WARN)
            except Exception:
                pass
            time.sleep(120)

    def scan_keylogger_autostarts(self):
        if not IS_WIN:
            return
        try:
            import winreg
        except Exception:
            return
        reg_paths = [r"Software\\Microsoft\\Windows\\CurrentVersion\\Run", r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"]
        suspicious = ["keylog","logger","keystroke","spy","capture"]
        while self.is_monitoring.get():
            try:
                for reg_path in reg_paths:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path)
                        for i in range(0, winreg.QueryInfoKey(key)[1]):
                            name, value, _ = winreg.EnumValue(key, i)
                            if any(s in (value or "").lower() or s in (name or "").lower() for s in suspicious):
                                self._log_color(f"⚠️ Suspicious autostart in registry: {name} → {value}", FG_WARN)
                        winreg.CloseKey(key)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(180)

    def monitor_honeytoken(self):
        if CONFIG.get("enable_txt"):
            _create_txt_honeytoken(CONFIG.get("txt_path"), self._log_color)
        while self.is_monitoring.get():
            path = CONFIG.get("txt_path")
            try:
                if path and os.path.exists(path):
                    last_access = os.path.getatime(path)
                    if last_access > self.start_time:
                        self._log_color(f"⚠️ Honeytoken was opened! {path}", FG_BAD)
            except Exception:
                pass
            time.sleep(25)

    def check_dns_leaks(self):
        if not IS_WIN:
            return
        try:
            output = subprocess.check_output("ipconfig /all", shell=True, encoding="utf-8", errors="ignore")
            for line in output.splitlines():
                # Match German "DNS-Server" and English "DNS Servers" and common public DNS IPs
                if ("DNS-Server" in line or "DNS Servers" in line) or re.search(r"(8\\.8\\.8\\.8|1\\.1\\.1\\.1|9\\.9\\.9\\.9)", line):
                    self._log_color(f"⚠️ Possible DNS leak: {line.strip()}", FG_WARN)
        except Exception as e:
            self._log_color(f"❌ DNS leak check error: {e}", FG_BAD)

    # TOR
    def refresh_tor_ips_periodically(self):
        while self.is_monitoring.get():
            try:
                import urllib.request
                resp = urllib.request.urlopen("https://check.torproject.org/exit-addresses", timeout=6).read().decode()
                self.known_tor_ips = {line.split()[1] for line in resp.splitlines() if line.startswith("ExitAddress")}
                self.log(f"TOR exit list updated ({len(self.known_tor_ips)})", FG_MUTED)
            except Exception:
                self.known_tor_ips = set()
            time.sleep(3600)

    def detect_tor_traffic(self):
        self.known_tor_ips = getattr(self, "known_tor_ips", set())
        while self.is_monitoring.get():
            try:
                for conn in psutil.net_connections(kind='inet'):
                    ip = conn.raddr.ip if conn.raddr else None
                    pid = conn.pid
                    if ip and pid and ip in self.known_tor_ips:
                        try:
                            pname = psutil.Process(pid).name()
                        except Exception:
                            pname = "Unknown"
                        self._log_color(f"⚠️ TOR connection detected: {pname} (PID {pid}) → {ip}", FG_BAD)
            except Exception:
                pass
            time.sleep(30)

    # ---------- Crypto Helpers (optional) ----------
    def encrypt_and_quit(self):
        if encrypt_data is None:
            self.log("❌ Encryption not available (nullcrypto_gui missing).", FG_BAD)
            return
        pw = ctk.CTkInputDialog(text="Encryption password:", title="Encrypt & Exit").get_input()
        if not pw:
            self.log("⚠️ No password entered.", FG_WARN)
            return
        files = ["whitelist.txt", MODEL_FILE, "watchdog.log", APP_CONFIG_FILE]
        for file in files:
            if os.path.exists(file):
                with open(file, "rb") as f:
                    data = f.read()
                enc = encrypt_data(data, pw)
                with open(file + ".scube", "wb") as f:
                    f.write(enc)
                try:
                    os.remove(file)
                except Exception:
                    pass
                self.log(f"🔒 {file} encrypted.", ACCENT)
        self.log("✅ All sensitive files encrypted. Exiting …", ACCENT)
        self.destroy()

    def decrypt_and_reload(self):
        if decrypt_data is None:
            self.log("❌ Decryption not available (nullcrypto_gui missing).", FG_BAD)
            return
        pw = ctk.CTkInputDialog(text="Password to decrypt:", title="Decrypt & Reload").get_input()
        if not pw:
            self.log("⚠️ No password entered.", FG_WARN)
            return
        files = [
            ("whitelist.txt.scube", "whitelist.txt"),
            (f"{MODEL_FILE}.scube", MODEL_FILE),
            ("watchdog.log.scube", "watchdog.log"),
            (APP_CONFIG_FILE + ".scube", APP_CONFIG_FILE)
        ]
        found = False
        for enc, dec in files:
            if os.path.exists(enc):
                found = True
                with open(enc, "rb") as f:
                    blob = f.read()
                try:
                    data = decrypt_data(blob, pw)
                    with open(dec, "wb") as f:
                        f.write(data)
                    os.remove(enc)
                    self.log(f"✅ {dec} decrypted & loaded.", ACCENT)
                except Exception as e:
                    self.log(f"❌ Error with {enc}: {e}", FG_BAD)
        if not found:
            self.log("No encrypted files found.", FG_WARN)
        else:
            self.log("🔁 Reload recommended.", FG_WARN)

    # ---------- Helpers ----------
    def _set_state(self, state):
        self.lbl_state.configure(text=state)
        self.state_label.configure(text=f"Status: {state}")
        if state == "running":
            self.state_label.configure(text_color=ACCENT)
        elif state == "stopped":
            self.state_label.configure(text_color=FG_BAD)
        else:
            self.state_label.configure(text_color=FG_MUTED)

    def _tick(self):
        self.time_label.configure(text=time.strftime("%Y-%m-%d %H:%M:%S"))
        self.after(250, self._tick)

    def _emit_dummy_events(self):
        self._log_color("🔧 Dummy: initialization …", FG_MUTED)
        self._log_color("ℹ️ Dummy: system check ok", ACCENT)
        self._log_color("⚠️ Dummy: test warning (keylogger heuristic)", FG_WARN)
        self._log_color("✅ Dummy: ready. Start when you want.", ACCENT)

# ======== run ========
if __name__ == "__main__":
    app = AIWatchdogApp()
    app.mainloop()
