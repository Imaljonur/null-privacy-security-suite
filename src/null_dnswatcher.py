# dnswatcher_ctk.py
# ∅DNSWatcher – CustomTkinter GUI in your Nullsearch style (dark + green)

import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
from scapy.all import AsyncSniffer, DNSQR, IP, IPv6
import threading, queue, time, re, csv, sys

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

# ==========================
# Design / Theme (dark+green)
# ==========================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")  # grelle Akzentfarbe wie nullsearch

ACCENT        = "#00FF88"
BG_DARK       = "#0B0F10"
BG_CARD       = "#12171A"
FG_TEXT       = "#D7E0E6"
FG_MUTED      = "#8FA3AD"
FG_TRACKER    = "#FF5C7C"
FG_SUSPICIOUS = "#FFCC66"
FG_OK         = "#7CE38B"
BORDER        = "#1D252B"

# ===========
# Heuristiken
# ===========
TRACKER_PATTERNS = [
    r"doubleclick\.net",
    r"graph\.facebook\.com",
    r"analytics\.",
    r"\.cloudfront\.net",
    r"tiktokcdn\.com",
    r"datadoghq\.com",
    r"googletagmanager\.com",
    r"adservice\.google\.com",
    r"googlesyndication\.com",
]
TRACKER_REGEX = re.compile("|".join(TRACKER_PATTERNS), re.I)

KEYWORDS = ["track", "ads", "pixel", "beacon", "log", "stats", "metrics", "collect"]

def is_suspicious(domain: str) -> bool:
    dl = domain.lower()
    return any(k in dl for k in KEYWORDS)

# ===========
# App class
# ===========
class DNSWatcherApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("∅ DNSWatcher")
        self.geometry("1120x720")
        self.configure(fg_color=BG_DARK)

        # State
        self.sniffer = None
        self.running = False
        self.pkt_queue = queue.Queue()
        self.domains_seen = set()
        self.counters = {"total":0, "trackers":0, "susp":0, "unique":0}

        # Layout: Sidebar + Main
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._build_statusbar()

        # Periodic UI updates
        self.after(100, self._drain_queue)

    # ------------- UI Build -------------
    def _card(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=14, border_color=BORDER, border_width=1)
        return frame

    def _build_sidebar(self):
        self.sidebar = self._card(self)
        self.sidebar.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        for r in range(20):
            self.sidebar.grid_rowconfigure(r, weight=0)
        self.sidebar.grid_rowconfigure(19, weight=1)
        self.sidebar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.sidebar, text="∅ DNSWatcher", text_color=ACCENT, font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, padx=16, pady=(16,6), sticky="w")
        ctk.CTkLabel(self.sidebar, text="Live DNS Requests", text_color=FG_MUTED).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

        self.iface_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Interface (e.g., eth0, en0, wlan0)")
        self.iface_entry.grid(row=2, column=0, padx=16, pady=(0,10), sticky="ew")

        self.filter_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Domain/Regex Filter (optional)")
        self.filter_entry.grid(row=3, column=0, padx=16, pady=(0,10), sticky="ew")

        self.only_new_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(self.sidebar, text="Show only new domains", variable=self.only_new_var).grid(row=4, column=0, padx=16, pady=(0,10), sticky="w")

        self.btn_start = ctk.CTkButton(self.sidebar, text="▶ Start", fg_color=ACCENT, text_color="black", command=self.start_sniffing)
        self.btn_start.grid(row=5, column=0, padx=16, pady=(6,6), sticky="ew")

        self.btn_stop = ctk.CTkButton(self.sidebar, text="⏸ Stop", fg_color="#1F2933", hover_color="#25313B", command=self.stop_sniffing)
        self.btn_stop.grid(row=6, column=0, padx=16, pady=(0,6), sticky="ew")

        self.btn_clear = ctk.CTkButton(self.sidebar, text="🧹 Clear", fg_color="#1F2933", hover_color="#25313B", command=self.clear_all)
        self.btn_clear.grid(row=7, column=0, padx=16, pady=(0,6), sticky="ew")

        self.btn_export = ctk.CTkButton(self.sidebar, text="⭳ Export CSV", fg_color="#1F2933", hover_color="#25313B", command=self.export_csv)
        self.btn_export.grid(row=8, column=0, padx=16, pady=(0,16), sticky="ew")

        # Legend
        legend = self._card(self.sidebar)
        legend.grid(row=9, column=0, padx=16, pady=(0,16), sticky="ew")
        ctk.CTkLabel(legend, text="Legend", text_color=FG_MUTED).pack(anchor="w", padx=12, pady=(10,2))
        ctk.CTkLabel(legend, text="• Tracker", text_color=FG_TRACKER).pack(anchor="w", padx=12)
        ctk.CTkLabel(legend, text="• Suspicious", text_color=FG_SUSPICIOUS).pack(anchor="w", padx=12)
        ctk.CTkLabel(legend, text="• OK", text_color=FG_OK).pack(anchor="w", padx=12, pady=(0,10))

        ctk.CTkLabel(self.sidebar, text="Note: Root/Admin privileges required for sniffing.", text_color=FG_MUTED, wraplength=220, font=ctk.CTkFont(size=12)).grid(row=18, column=0, padx=16, pady=(0,16), sticky="w")

    def _build_main(self):
        self.main = self._card(self)
        self.main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(self.main, fg_color=BG_CARD)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
        header.grid_columnconfigure(0, weight=1)
        self.state_label = ctk.CTkLabel(header, text="Status: idle", text_color=FG_MUTED)
        self.state_label.grid(row=0, column=0, sticky="w")
        self.time_label = ctk.CTkLabel(header, text="", text_color=FG_MUTED)
        self.time_label.grid(row=0, column=1, sticky="e", padx=6)

        # Tree (table view)
        table_frame = ctk.CTkFrame(self.main, fg_color=BG_CARD)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("default")
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

        columns = ("time", "src", "qname", "type", "flag")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.heading("time", text="Time")
        self.tree.heading("src",  text="Source")
        self.tree.heading("qname",text="Domain")
        self.tree.heading("type", text="Typee")
        self.tree.heading("flag", text="Classification")

        self.tree.column("time", width=130, anchor="w")
        self.tree.column("src",  width=140, anchor="w")
        self.tree.column("qname",width=520, anchor="w")
        self.tree.column("type", width=60,  anchor="center")
        self.tree.column("flag", width=120, anchor="w")

        # Scrollbar
        vsb = ctk.CTkScrollbar(table_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.grid(row=0, column=1, sticky="ns")

        # Row tags / colors
        self.tree.tag_configure("tracker", foreground=FG_TRACKER)
        self.tree.tag_configure("suspicious", foreground=FG_SUSPICIOUS)
        self.tree.tag_configure("ok", foreground=FG_OK)

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

        self.box_total, self.lbl_total   = metric("Requests", "0")
        self.box_track, self.lbl_track   = metric("Tracker", "0")
        self.box_susp,  self.lbl_susp    = metric("Suspicious", "0")
        self.box_unique,self.lbl_unique  = metric("Unique Domains", "0")
        self.box_state, self.lbl_state   = metric("Sniffer", "idle")

        self.box_total.grid(row=0, column=0, sticky="ew", padx=(0,8))
        self.box_track.grid(row=0, column=1, sticky="ew", padx=8)
        self.box_susp.grid(row=0, column=2, sticky="ew", padx=8)
        self.box_unique.grid(row=0, column=3, sticky="ew", padx=8)
        self.box_state.grid(row=0, column=4, sticky="ew", padx=(8,0))

    # ------------- Sniffing -------------
    def start_sniffing(self):
        if self.running:
            return
        iface = self.iface_entry.get().strip() or None
        self.sniffer = AsyncSniffer(filter="udp port 53", prn=self._on_packet, store=False, iface=iface)
        try:
            self.sniffer.start()
            self.running = True
            self._set_state("running")
        except Exception as e:
            messagebox.showerror("Error", f"Could not start sniffer:\n{e}")
            self._set_state("error")

    def stop_sniffing(self):
        if not self.running:
            return
        try:
            self.sniffer.stop()
        except Exception:
            pass
        self.running = False
        self._set_state("stopped")

    def clear_all(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.domains_seen.clear()
        for k in self.counters:
            self.counters[k] = 0
        self._sync_counters()

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path:
            return
        rows = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            rows.append(vals)
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["time","src","qname","type","flag"])
                writer.writerows(rows)
            messagebox.showinfo("Export", f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Export", f"Error while saving:\n{e}")

    # ------------- Callbacks / Internal -------------
    def _on_packet(self, pkt):
        # runs in sniffer thread -> enqueue
        try:
            if (IP in pkt or IPv6 in pkt) and pkt.haslayer(DNSQR):
                src = pkt[IP].src if IP in pkt else pkt[IPv6].src
                qn  = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                qtype = pkt[DNSQR].qtype
                self.pkt_queue.put((time.time(), src, qn, qtype))
        except Exception:
            pass

    def _drain_queue(self):
        # runs in UI thread
        while True:
            try:
                ts, src, qn, qtype = self.pkt_queue.get_nowait()
            except queue.Empty:
                break

            # Filter/Only new
            if self.only_new_var.get() and qn in self.domains_seen:
                continue

            flt = self.filter_entry.get().strip()
            if flt:
                try:
                    if not re.search(flt, qn, re.I):
                        continue
                except re.error:
                    # invalid regex -> treat like no filter
                    pass

            tag, flagtext = self._classify(qn)
            if qn not in self.domains_seen:
                self.domains_seen.add(qn)
                self.counters["unique"] = len(self.domains_seen)

            self.counters["total"] += 1
            if tag == "tracker": self.counters["trackers"] += 1
            elif tag == "suspicious": self.counters["susp"] += 1

            tstr = time.strftime("%H:%M:%S", time.localtime(ts))
            self.tree.insert("", "end", values=(tstr, src, qn, qtype, flagtext), tags=(tag,))
            # Realtime emit to Sentinel (UDP)
            level = "info"
            if tag == "tracker": level = "alert"
            elif tag == "suspicious": level = "warn"
            sentinel({
                "ts": _utcnow_iso(),
                "tool": "dnswatcher",
                "level": level,
                "host": "",
                "pid": 0,
                "msg": f"DNS query: {qn}",
                "labels": {"domain": qn, "ip": src, "qtype": str(qtype), "flag": flagtext}
            })

            # Auto-scroll
            self.tree.yview_moveto(1.0)
            self._sync_counters()

        # Status clock
        self.time_label.configure(text=time.strftime("%Y-%m-%d %H:%M:%S"))
        self.after(120, self._drain_queue)

    def _classify(self, domain: str):
        if TRACKER_REGEX.search(domain):
            return "tracker", "Tracker"
        if is_suspicious(domain):
            return "suspicious", "Suspicious"
        return "ok", "OK"

    def _sync_counters(self):
        self.lbl_total.configure(text=str(self.counters["total"]))
        self.lbl_track.configure(text=str(self.counters["trackers"]))
        self.lbl_susp.configure(text=str(self.counters["susp"]))
        self.lbl_unique.configure(text=str(self.counters["unique"]))

    def _set_state(self, state: str):
        self.lbl_state.configure(text=state)
        self.state_label.configure(text=f"Status: {state}")
        if state == "running":
            self.state_label.configure(text_color=ACCENT)
        elif state == "error":
            self.state_label.configure(text_color=FG_TRACKER)
        else:
            self.state_label.configure(text_color=FG_MUTED)

if __name__ == "__main__":
    try:
        app = DNSWatcherApp()
        app.mainloop()
    except KeyboardInterrupt:
        sys.exit(0)