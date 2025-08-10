
import psutil
import subprocess
import threading
import socket
import ipaddress
import customtkinter as ctk
from tkinter import ttk, messagebox

# ∅PortBlocker – GUI Firewall: Block outgoing connections by process, port, or IP range
# Windows implementation using netsh advfirewall commands
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

class PortBlockerApp:
    def __init__(self, root):
        self.root = root
        _theme_setup()
        self.root.title("∅PortBlocker")
        self.root.geometry("1100x720")
        self.root.configure(fg_color=BG_DARK)

        # Layout grid: Sidebar | Main
        self.root.grid_columnconfigure(0, weight=0)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=0)

        # Sidebar
        sb = _card(self.root)
        sb.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        sb.grid_columnconfigure(0, weight=1)

        _title(sb, "∅ PortBlocker").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        _label(sb, "Block IP / Port / Process", muted=True).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

        _btn_primary(sb, "🔄 Refresh", self.refresh).grid(row=2, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "🛑 Block IP", self.block_ip).grid(row=3, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "🚫 Block Port", self.block_port).grid(row=4, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "🔒 Block Process", self.block_process).grid(row=5, column=0, padx=16, pady=(0,16), sticky="ew")

        # Main Card with Tree
        main = _card(self.root)
        main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(main, fg_color=BG_CARD)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
        header.grid_columnconfigure(0, weight=1)
        self.status = _label(header, "Ready", muted=True)
        self.status.grid(row=0, column=0, sticky="w")

        body = ctk.CTkFrame(main, fg_color=BG_CARD)
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # Styling for ttk Treeview
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Treeview",
                        background=BG_CARD,
                        foreground=FG_TEXT,
                        fieldbackground=BG_CARD,
                        rowheight=26,
                        font=("Consolas", 10))
        style.map('Treeview', background=[('selected', '#23313A')])
        style.configure("Treeview.Heading",
                        background=BG_CARD,
                        foreground=ACCENT,
                        font=("Consolas", 11, "bold"))

        cols = ("PID", "Process", "Local Address", "Remote Address", "Port")
        self.tree = ttk.Treeview(body, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=180 if c in ("Process","Remote Address") else 140, anchor="w")
        self.tree.tag_configure("warn", background="#3A2020", foreground="#FF8080")
        self.tree.grid(row=0, column=0, sticky="nsew")

        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.grid(row=0, column=1, sticky="ns")

        # Statusbar
        statusbar = _card(self.root)
        statusbar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
        statusbar.grid_columnconfigure(0, weight=1)
        _label(statusbar, "Tip: Select an entry, then choose an action in the sidebar.", muted=True).grid(row=0, column=0, padx=12, pady=10, sticky="w")

        threading.Thread(target=self.refresh, daemon=True).start()

    # ===== Original logic below (unchanged, except .configure for CTk) =====
    def refresh(self):
        self.status.configure(text="🔄 Loading connections...")
        # Populate active connections
        for i in self.tree.get_children():
            self.tree.delete(i)
        for conn in psutil.net_connections(kind='inet'):
            pid = conn.pid or ""
            try:
                proc = psutil.Process(pid).name() if pid else ""
            except:
                proc = ""
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            port = conn.raddr.port if conn.raddr else ""
            tags = ()
            # Warn if port high or unknown
            if port and port > 49152:
                tags = ("warn",)
            self.tree.insert("", "end", values=(pid, proc, laddr, raddr, port), tags=tags)
        self.status.configure(text="✅ Connections updated")

    def block_ip(self):
        sel = self.tree.selection()
        if not sel: return
        ip = self.tree.item(sel[0])['values'][3].split(':')[0]
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=BlockIP_{ip}", "dir=out", "action=block", f"remoteip={ip}"]
        subprocess.run(cmd, shell=True)
        messagebox.showinfo("Blocked", f"IP {ip} has been blocked")

    def block_port(self):
        sel = self.tree.selection()
        if not sel: return
        port = self.tree.item(sel[0])['values'][4]
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=BlockPort_{port}", "dir=out", "action=block", f"remoteport={port}"]
        subprocess.run(cmd, shell=True)
        messagebox.showinfo("Blocked", f"Port {port} has been blocked")

    def block_process(self):
        sel = self.tree.selection()
        if not sel: return
        pid = self.tree.item(sel[0])['values'][0]
        proc = self.tree.item(sel[0])['values'][1]
        # Finde den Pfad
        try:
            path = psutil.Process(pid).exe()
        except:
            path = ""
        rule = f"BlockProc_{proc}_{pid}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule}", "dir=out", "action=block", f"program={path}"]
        subprocess.run(cmd, shell=True)
        messagebox.showinfo("Blocked", f"Process {proc} has been blocked")

if __name__ == "__main__":
    root = ctk.CTk()
    app = PortBlockerApp(root)
    root.mainloop()
