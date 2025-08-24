
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import socket
import ipaddress
from scapy.all import ARP, Ether, srp, sr1, ICMP, IP
import requests
import customtkinter as ctk

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

# ∅NetworkScanner v2 – ARP scan + port, OS & vendor detection
# Extension: automatic vendor lookup via macvendors API, caching
# NOTE: Only GUI/layout changed to CustomTkinter Nullsearch style. Logic unchanged.

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

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        _theme_setup()
        self.root.title("∅NetworkScanner v2")
        self.root.geometry("1100x720")
        self.root.configure(fg_color=BG_DARK)

        # Layout grid: Sidebar | Main
        self.root.grid_columnconfigure(0, weight=0)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        sb = _card(self.root)
        sb.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        sb.grid_columnconfigure(0, weight=1)

        _title(sb, "∅ NetworkScanner").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        _label(sb, "ARP scan · Ports · OS · Vendor", muted=True).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

        # Auto-Detection des lokalen /24-Netzes (unchanged logic)
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            default_net = local_ip.rsplit('.',1)[0] + '.0/24'
        except:
            default_net = '192.168.1.0/24'
        self.network_var = tk.StringVar(value=default_net)

        net_card = _card(sb)
        net_card.grid(row=2, column=0, padx=16, pady=(0,12), sticky="ew")
        net_card.grid_columnconfigure(0, weight=1)
        _label(net_card, "Network (e.g., 192.168.1.0/24):", muted=True).grid(row=0, column=0, padx=10, pady=(10,4), sticky="w")
        self.net_entry = ctk.CTkEntry(net_card, textvariable=self.network_var, placeholder_text="192.168.1.0/24")
        self.net_entry.grid(row=1, column=0, padx=10, pady=(0,10), sticky="ew")

        _btn_primary(sb, "▶ Start scan", self.start_scan).grid(row=3, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "✖ Stop", self.stop_scan).grid(row=4, column=0, padx=16, pady=(0,16), sticky="ew")

        # --- Main Card ---
        main = _card(self.root)
        main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(main, fg_color=BG_CARD)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
        header.grid_columnconfigure(0, weight=1)
        _label(header, "Results (double-click Vendor/OS to edit)", muted=True).grid(row=0, column=0, sticky="w")

        # Style Treeview (dark)
        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass
        style.configure("Treeview", background=BG_CARD, foreground=FG_TEXT, fieldbackground=BG_CARD, rowheight=24, font=("Consolas",10))
        style.map('Treeview', background=[('selected','#23313A')])
        style.configure("Treeview.Heading", background=BG_CARD, foreground=ACCENT, font=("Consolas",11,"bold"))

        # Table with editable OS and Vendor columns (unchanged columns)
        cols = ("IP", "Hostname", "MAC", "Vendor", "OS", "Open Ports")
        self.tree = ttk.Treeview(main, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=160 if c!="Open Ports" else 200, anchor='w')
        self.tree.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
        self.tree.tag_configure("open", background="#004400", foreground="#00FF00")

        # Bind double-click for editing Vendor (col #4) and OS (col #5) (unchanged handler)
        self.tree.bind('<Double-1>', self.on_double_click)

        # Ports and vendor cache (unchanged)
        self.ports = [22, 80, 443]
        self.vendor_cache = {}
        self.scanning = False

    # ============ LOGIC BELOW UNCHANGED ============
    def on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not item: return
        if col in ('#4', '#5'):
            col_name = 'Vendor' if col=='#4' else 'OS'
            old = self.tree.set(item, col_name)
            new = simpledialog.askstring(f"{col_name} edit", f"Gib {col_name} ein:", initialvalue=old)
            if new is not None:
                self.tree.set(item, col_name, new)

    def start_scan(self):
        if self.scanning: return
        self.scanning = True
        self.tree.delete(*self.tree.get_children())
        try:
            network = ipaddress.ip_network(self.network_var.get(), strict=False)
        except:
            messagebox.showerror("Error","Invalid network")
            self.scanning=False
            return
        threading.Thread(target=self.scan_network, args=(network,), daemon=True).start()

    def stop_scan(self):
        self.scanning = False

    def detect_os(self, ip):
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if pkt and hasattr(pkt,'ttl'):
            ttl = pkt.ttl
            if ttl >= 128: return 'Windows'
            if ttl >= 64: return 'Linux'
            if ttl >= 255: return 'Cisco'
        return 'Unknown'

    def lookup_vendor(self, mac):
        oui = mac.upper()[0:8]
        if oui in self.vendor_cache:
            return self.vendor_cache[oui]
        try:
            resp = requests.get(f'https://api.macvendors.com/{mac}', timeout=2)
            if resp.status_code == 200:
                vendor = resp.text
            else:
                vendor = 'Unknown'
        except:
            vendor = 'Unknown'
        self.vendor_cache[oui] = vendor
        return vendor

    def scan_network(self, network):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(network)), timeout=2, verbose=0)
        for snd, rcv in ans:
            if not self.scanning: break
            ip = rcv.psrc; mac = rcv.hwsrc
            try: host = socket.gethostbyaddr(ip)[0]
            except: host = '-'
            vendor = self.lookup_vendor(mac)
            os_type = self.detect_os(ip)
            open_ports = []
            for p in self.ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.3)
                    if sock.connect_ex((ip, p)) == 0:
                        open_ports.append(str(p))
            ports_str = ','.join(open_ports) if open_ports else '-'
            tag = ('open',) if open_ports else ()
            self.tree.insert('', tk.END, values=(ip, host, mac, vendor, os_type, ports_str), tags=tag)
            # Realtime emit to Sentinel (UDP)
            sentinel({
                "ts": _utcnow_iso(),
                "tool": "networkscan",
                "level": "warn" if open_ports else "info",
                "host": "",
                "pid": 0,
                "msg": f"scan host: {ip} ({host})",
                "labels": {"ip": ip, "host": host, "mac": mac, "vendor": vendor, "os": os_type, "open_ports": ports_str}
            })
        if not ans:
            messagebox.showinfo("Result","No hosts found.")
        self.scanning = False

if __name__=='__main__':
    root = ctk.CTk()
    app = NetworkScannerApp(root)
    root.mainloop()
