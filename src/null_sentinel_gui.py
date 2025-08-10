
import customtkinter as ctk
import subprocess
import threading

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
#  APP (FUNCTIONS UNCHANGED)
# =========================
_theme_setup()

app = ctk.CTk()
app.title("∅ Sentinel")
app.geometry("900x640")
app.configure(fg_color=BG_DARK)

# Tabs
tabview = ctk.CTkTabview(app, width=860, height=580)
tabview.pack(padx=14, pady=14, fill="both", expand=True)
tabview.add("🟢 Monitor")
tabview.add("💬 Messenger")
tabview.add("🔐 Crypto")
tabview.add("🕸 Network")
tabview.add("☣️ Processes")
tabview.add("🚨 Alarms")

# --- Messenger Tab ---
messenger_tab = tabview.tab("💬 Messenger")
messenger_tab.grid_columnconfigure(0, weight=1)
card_msg = _card(messenger_tab)
card_msg.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_msg.grid_columnconfigure(0, weight=1)
_title(card_msg, "Start secure messenger").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_null_messenger():
    threading.Thread(target=lambda: subprocess.run(["python", "null_messenger.py"])).start()

_btn(card_msg, "Start ∅ null_messenger", run_null_messenger).grid(row=1, column=0, sticky="n", padx=14, pady=(0,14))

# --- Monitor Tab ---
monitor_tab = tabview.tab("🟢 Monitor")
monitor_tab.grid_columnconfigure(0, weight=1)
card_mon = _card(monitor_tab); card_mon.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_mon.grid_columnconfigure(0, weight=1)
_title(card_mon, "Live monitoring tools").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_dnswatch():
    threading.Thread(target=lambda: subprocess.run(["python", "null_dnswatcher.py"])).start()
def run_ramprotect():
    threading.Thread(target=lambda: subprocess.run(["python", "null_protect_ram_gui.py"])).start()

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
    threading.Thread(target=lambda: subprocess.run(["python", "nullcrypto_gui.py"])).start()
_btn(card_crypto, "Open ∅Crypto", run_crypto).grid(row=1, column=0, sticky="n", padx=14, pady=(0,14))

# --- Network Tab ---
network_tab = tabview.tab("🕸 Network")
network_tab.grid_columnconfigure(0, weight=1)
card_net = _card(network_tab); card_net.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_net.grid_columnconfigure(0, weight=1)
_title(card_net, "Network Tools").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_netmon():
    threading.Thread(target=lambda: subprocess.run(["python", "null_netmon.py"])).start()
def run_netscan():
    threading.Thread(target=lambda: subprocess.run(["python", "null_networkscan.py"])).start()
def run_firewall_visualizer():
    threading.Thread(target=lambda: subprocess.run(["python", "null_firewallvisualizer.py"])).start()
def run_file_watchdog():
    threading.Thread(target=lambda: subprocess.run(["python", "null_filewatchdog.py"])).start()

r = 1
_btn(card_net, "Start Net Monitor", run_netmon).grid(row=r, column=0, sticky="n", padx=14, pady=6); r += 1
_btn(card_net, "Run Network Scan", run_netscan).grid(row=r, column=0, sticky="n", padx=14, pady=6); r += 1
_btn(card_net, "Start firewall visualizer", run_firewall_visualizer).grid(row=r, column=0, sticky="n", padx=14, pady=6); r += 1
_btn(card_net, "Start file watchdog", run_file_watchdog).grid(row=r, column=0, sticky="n", padx=14, pady=(0,14)); r += 1

def run_null_scanner():
    threading.Thread(target=lambda: subprocess.run(["python", "null_scanner.py"])).start()
_btn(card_net, "Start Null Scanner", run_null_scanner).grid(row=r, column=0, sticky="n", padx=14, pady=6); r += 1
# --- Processes Tab ---
process_tab = tabview.tab("☣️ Processes")
process_tab.grid_columnconfigure(0, weight=1)
card_proc = _card(process_tab); card_proc.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_proc.grid_columnconfigure(0, weight=1)
_title(card_proc, "Process Control Tools").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_portblock():
    threading.Thread(target=lambda: subprocess.run(["python", "null_PortBlocker.py"])).start()
def run_procguard():
    threading.Thread(target=lambda: subprocess.run(["python", "null_processguard_v2.py"])).start()

_btn(card_proc, "Open Port Blocker", run_portblock).grid(row=1, column=0, sticky="n", padx=14, pady=6)
_btn(card_proc, "Start Process Guard", run_procguard).grid(row=2, column=0, sticky="n", padx=14, pady=(0,14))

# --- Alarms Tab ---
alarms_tab = tabview.tab("🚨 Alarms")
alarms_tab.grid_columnconfigure(0, weight=1)
card_alarm = _card(alarms_tab); card_alarm.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
card_alarm.grid_columnconfigure(0, weight=1)
_title(card_alarm, "Live Alerts & AI Watchdog").grid(row=0, column=0, sticky="n", padx=14, pady=(14,6))

def run_ai_watchdog():
    threading.Thread(target=lambda: subprocess.run(["python", "null_ai_watchdog_gui.py"])).start()
def run_nullsearch():
    threading.Thread(target=lambda: subprocess.run(["python", "nullsearch.py"])).start()

_btn(card_alarm, "Start ∅AI Watchdog", run_ai_watchdog).grid(row=1, column=0, sticky="n", padx=14, pady=6)
_btn(card_alarm, "Run ∅Search", run_nullsearch).grid(row=2, column=0, sticky="n", padx=14, pady=(0,14))

app.mainloop()
