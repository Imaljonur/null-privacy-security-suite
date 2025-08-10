# firewallvisualizer_ctk_en.py
# ∅ Firewall Visualizer – CustomTkinter (Nullsearch Dark/Green)
# Note: Windows required (netsh). Admin rights needed.

import sys, os, subprocess, threading, queue, time, csv, ctypes, platform, re
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox

# ========= Theme (dark + green) =========
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

ACCENT        = "#00FF88"
BG_DARK       = "#0B0F10"
BG_CARD       = "#12171A"
FG_TEXT       = "#D7E0E6"
FG_MUTED      = "#8FA3AD"
FG_OK         = "#7CE38B"
FG_BAD        = "#FF5C7C"
BORDER        = "#1D252B"

IS_WIN = platform.system().lower().startswith("win")

# ========= Admin Elevation (Windows) =========
def ensure_admin_windows():
    if not IS_WIN:
        return
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            # Relaunch as admin
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)
    except Exception:
        pass

# ========= Rule Loading (netsh) =========
def load_rules_via_netsh():
    """
    Returns list of dicts:
    [{"name":..., "dir":..., "action":..., "program":..., "profile":..., "localport":..., "remoteport":...}, ...]
    """
    if not IS_WIN:
        return []
    try:
        # Accept both German and English output; match by known labels and fall back.
        # netsh advfirewall firewall show rule name=all
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore"
        )
        output = result.stdout + result.stderr
        if not output.strip():
            return []
        chunks = output.split("Regelname:")[1:] or output.split("Rule Name:")[1:]
        rules = []
        for ch in chunks:
            lines = [ln.strip() for ln in ch.strip().splitlines() if ln.strip()]
            if not lines:
                continue
            name = lines[0]

            def find_value(keys):
                for key in keys:
                    for ln in lines:
                        if ln.lower().startswith(key.lower()):
                            # key like "Richtung:" or "Direction:"
                            parts = ln.split(":", 1)
                            if len(parts) == 2:
                                return parts[1].strip()
                return "Unknown"

            direction = find_value(["Richtung", "Direction"])
            action    = find_value(["Aktion", "Action"])
            program   = find_value(["Programm", "Program"])
            profile   = find_value(["Profil", "Profile"])
            lport     = find_value(["Lokaler Port", "LocalPort", "Lokaler Port (Local Port)"])
            rport     = find_value(["Remoteport", "Remote Port", "Remoteport (Remote Port)"])

            # Normalize action text
            al = action.lower()
            if "allow" in al or "zulassen" in al or "zugelassen" in al:
                action_norm = "Allow"
            elif "block" in al or "blockieren" in al or "blockiert" in al:
                action_norm = "Block"
            else:
                action_norm = action

            rules.append({
                "name": name,
                "dir": direction,
                "action": action_norm,
                "program": program if program and program != "Alle" else "(all)",
                "profile": profile,
                "localport": lport,
                "remoteport": rport
            })
        return rules
    except Exception:
        return []

# ========= App =========
class FirewallVisualizer(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("∅ Firewall Visualizer")
        self.geometry("1200x750")
        self.configure(fg_color=BG_DARK)

        # State
        self.rules = []                # full list of dicts
        self.filtered_rules = []       # view list
        self.selected_name = None
        self.q = queue.Queue()
        self.counters = {"total":0, "allow":0, "block":0, "selected":0}
        self.running = False

        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._build_statusbar()

        # load async on start
        self.refresh_rules()
        self.after(150, self._ui_pulse)

    # ----- UI builders -----
    def _card(self, parent):
        return ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=14, border_color=BORDER, border_width=1)

    def _build_sidebar(self):
        self.sidebar = self._card(self)
        self.sidebar.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        self.sidebar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.sidebar, text="∅ Firewall Visualizer", text_color=ACCENT,
                     font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        ctk.CTkLabel(self.sidebar, text="Windows Firewall – visualize rules",
                     text_color=FG_MUTED).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

        # Filter
        self.filter_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Filter (name, app, direction, port, …)")
        self.filter_entry.grid(row=2, column=0, padx=16, pady=(0,10), sticky="ew")

        self.only_allowed = ctk.BooleanVar(value=False)
        self.only_blocked = ctk.BooleanVar(value=False)
        cbx_frame = self._card(self.sidebar)
        cbx_frame.grid(row=3, column=0, padx=16, pady=(0,10), sticky="ew")
        ctk.CTkCheckBox(cbx_frame, text="Only allow", variable=self.only_allowed, command=self.apply_filter)\
            .pack(anchor="w", padx=10, pady=(8,2))
        ctk.CTkCheckBox(cbx_frame, text="Only block", variable=self.only_blocked, command=self.apply_filter)\
            .pack(anchor="w", padx=10, pady=(0,8))

        # Buttons
        self.btn_apply = ctk.CTkButton(self.sidebar, text="🔍 Apply filter",
                                       fg_color="#1F2933", hover_color="#25313B",
                                       command=self.apply_filter)
        self.btn_apply.grid(row=4, column=0, padx=16, pady=(0,8), sticky="ew")

        self.btn_refresh = ctk.CTkButton(self.sidebar, text="↻ Refresh",
                                         fg_color="#1F2933", hover_color="#25313B",
                                         command=self.refresh_rules)
        self.btn_refresh.grid(row=5, column=0, padx=16, pady=(0,8), sticky="ew")

        self.btn_export = ctk.CTkButton(self.sidebar, text="⭳ Export CSV",
                                        fg_color="#1F2933", hover_color="#25313B",
                                        command=self.export_csv)
        self.btn_export.grid(row=6, column=0, padx=16, pady=(0,16), sticky="ew")

        # Actions
        actions = self._card(self.sidebar)
        actions.grid(row=7, column=0, padx=16, pady=(0,16), sticky="ew")
        ctk.CTkLabel(actions, text="Actions", text_color=FG_MUTED).pack(anchor="w", padx=12, pady=(10,2))

        self.btn_toggle = ctk.CTkButton(actions, text="Toggle Block/Allow", command=self.toggle_selected,
                                        fg_color=ACCENT, text_color="black")
        self.btn_toggle.pack(fill="x", padx=12, pady=(4,6))

        self.btn_delete = ctk.CTkButton(actions, text="Delete", command=self.delete_selected,
                                        fg_color="#B84C4C", hover_color="#A03E3E")
        self.btn_delete.pack(fill="x", padx=12, pady=(0,6))

        self.btn_copy = ctk.CTkButton(actions, text="Copy text", command=self.copy_selected,
                                      fg_color="#1F2933", hover_color="#25313B")
        self.btn_copy.pack(fill="x", padx=12, pady=(0,12))

        ctk.CTkLabel(self.sidebar, text="Tip: Double-click a rule to select it.",
                     text_color=FG_MUTED, font=ctk.CTkFont(size=12), wraplength=230)\
            .grid(row=8, column=0, padx=16, pady=(0,10), sticky="w")

        ctk.CTkLabel(self.sidebar, text="Note: Admin rights required (Windows).",
                     text_color=FG_MUTED, font=ctk.CTkFont(size=12))\
            .grid(row=9, column=0, padx=16, pady=(0,16), sticky="w")

    def _build_main(self):
        self.main = self._card(self)
        self.main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(self.main, fg_color=BG_CARD)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
        header.grid_columnconfigure(0, weight=1)
        self.state_label = ctk.CTkLabel(header, text="Status: loading…", text_color=FG_MUTED)
        self.state_label.grid(row=0, column=0, sticky="w")
        self.time_label = ctk.CTkLabel(header, text="", text_color=FG_MUTED)
        self.time_label.grid(row=0, column=1, sticky="e")

        # Table
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

        cols = ("name","dir","action","program","profile","lport","rport")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree.grid(row=0, column=0, sticky="nsew")

        self.tree.heading("name",   text="Rule name")
        self.tree.heading("dir",    text="Direction")
        self.tree.heading("action", text="Action")
        self.tree.heading("program",text="Program")
        self.tree.heading("profile",text="Profile")
        self.tree.heading("lport",  text="Local Port")
        self.tree.heading("rport",  text="Remote Port")

        self.tree.column("name",   width=320, anchor="w")
        self.tree.column("dir",    width=90,  anchor="center")
        self.tree.column("action", width=90,  anchor="center")
        self.tree.column("program",width=260, anchor="w")
        self.tree.column("profile",width=110, anchor="center")
        self.tree.column("lport",  width=90,  anchor="center")
        self.tree.column("rport",  width=110, anchor="center")

        vsb = ctk.CTkScrollbar(table_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.grid(row=0, column=1, sticky="ns")

        # Row tags
        self.tree.tag_configure("allow", foreground=FG_OK)
        self.tree.tag_configure("block", foreground=FG_BAD)

        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", self.on_double_click)

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

        self.box_total, self.lbl_total = metric("Rules", "0")
        self.box_allow, self.lbl_allow = metric("Allowed", "0")
        self.box_block, self.lbl_block = metric("Blocked", "0")
        self.box_sel,   self.lbl_sel   = metric("Selected", "0")
        self.box_state, self.lbl_state = metric("Status", "idle")

        self.box_total.grid(row=0, column=0, sticky="ew", padx=(0,8))
        self.box_allow.grid(row=0, column=1, sticky="ew", padx=8)
        self.box_block.grid(row=0, column=2, sticky="ew", padx=8)
        self.box_sel.grid(row=0, column=3, sticky="ew", padx=8)
        self.box_state.grid(row=0, column=4, sticky="ew", padx=(8,0))

    # ----- Actions -----
    def refresh_rules(self):
        if self.running:
            return
        self.running = True
        self._set_state("Loading…", "loading")
        threading.Thread(target=self._worker_load, daemon=True).start()

    def _worker_load(self):
        rules = load_rules_via_netsh()
        self.rules = rules
        self.q.put(("loaded", None))

    def apply_filter(self):
        kw = (self.filter_entry.get() or "").strip().lower()
        only_a = self.only_allowed.get()
        only_b = self.only_blocked.get()

        def match(rule):
            s = f"{rule['name']} {rule['dir']} {rule['action']} {rule['program']} {rule['profile']} {rule['localport']} {rule['remoteport']}".lower()
            if kw and kw not in s:
                return False
            if only_a and rule['action'].lower() != 'allow':
                return False
            if only_b and rule['action'].lower() != 'block':
                return False
            return True

        self.filtered_rules = [r for r in self.rules if match(r)]
        self._reload_table()
        self._update_counters()

    def _reload_table(self):
        self.tree.delete(*self.tree.get_children())
        for r in self.filtered_rules:
            tag = "allow" if r["action"].lower() == "allow" else "block"
            self.tree.insert("", "end",
                             values=(r["name"], r["dir"], r["action"], r["program"], r["profile"], r["localport"], r["remoteport"]),
                             tags=(tag,))
        # Autoscroll to top
        if self.filtered_rules:
            self.tree.yview_moveto(0.0)

    def on_select(self, _):
        sel = self.tree.selection()
        if not sel:
            self.selected_name = None
            self.lbl_sel.configure(text="0")
            return
        vals = self.tree.item(sel[0], "values")
        self.selected_name = vals[0]
        self.lbl_sel.configure(text="1")

    def on_double_click(self, _):
        self.on_select(_)
        if self.selected_name:
            self._flash_state(f"Selected: {self.selected_name}")

    def delete_selected(self):
        name = self.selected_name
        if not name:
            messagebox.showinfo("Info", "Please select a rule first.")
            return
        if not IS_WIN:
            messagebox.showerror("Error", "Delete is only available on Windows.")
            return
        if not messagebox.askyesno("Confirm", f"Really delete rule?\n{name}"):
            return
        try:
            subprocess.run(
                ["powershell", "-Command", f"Remove-NetFirewallRule -DisplayName '{name}'"],
                check=True
            )
            self._flash_state(f"Rule deleted: {name}")
            self.refresh_rules()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error while deleting:\n{e}")

    def toggle_selected(self):
        name = self.selected_name
        if not name:
            messagebox.showinfo("Info", "Please select a rule first.")
            return
        if not IS_WIN:
            messagebox.showerror("Error", "Toggle is only available on Windows.")
            return
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"(Get-NetFirewallRule -DisplayName '{name}' | Select-Object -ExpandProperty Action)"],
                capture_output=True, text=True
            )
            cur = (result.stdout or "").strip()
            new_action = "Block" if "Allow" in cur else "Allow"
            subprocess.run(
                ["powershell", "-Command", f"Set-NetFirewallRule -DisplayName '{name}' -Action {new_action}"],
                check=True
            )
            self._flash_state(f"{name} → {new_action}")
            self.refresh_rules()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error while toggling:\n{e}")

    def copy_selected(self):
        name = self.selected_name
        if not name:
            messagebox.showinfo("Info", "Please select a rule first.")
            return
        try:
            rule = next(r for r in self.filtered_rules if r["name"] == name)
        except StopIteration:
            return
        text = f"{rule['name']} | {rule['dir']} | {rule['action']} | {rule['program']} | {rule['profile']} | {rule['localport']} | {rule['remoteport']}"
        self.clipboard_clear()
        self.clipboard_append(text)
        self._flash_state("Rule copied")

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["name","direction","action","program","profile","localport","remoteport"])
                for r in self.filtered_rules:
                    w.writerow([r["name"], r["dir"], r["action"], r["program"], r["profile"], r["localport"], r["remoteport"]])
            self._flash_state(f"Exported: {path}")
        except Exception as e:
            messagebox.showerror("Export", f"Error while saving:\n{e}")

    # ----- Internals -----
    def _ui_pulse(self):
        # handle worker queue
        try:
            while True:
                msg, payload = self.q.get_nowait()
                if msg == "loaded":
                    self.running = False
                    self._set_state("Rules loaded.", "ok")
                    self.apply_filter()
        except queue.Empty:
            pass

        # clock
        self.time_label.configure(text=time.strftime("%Y-%m-%d %H:%M:%S"))
        self.after(150, self._ui_pulse)

    def _update_counters(self):
        total = len(self.filtered_rules)
        allow = sum(1 for r in self.filtered_rules if r["action"].lower() == "allow")
        block = sum(1 for r in self.filtered_rules if r["action"].lower() == "block")
        self.counters.update({"total": total, "allow": allow, "block": block})
        self.lbl_total.configure(text=str(total))
        self.lbl_allow.configure(text=str(allow))
        self.lbl_block.configure(text=str(block))

    def _set_state(self, text, kind="idle"):
        self.lbl_state.configure(text=kind)
        self.state_label.configure(text=f"Status: {text}")
        if kind == "ok":
            self.state_label.configure(text_color=ACCENT)
        elif kind == "error":
            self.state_label.configure(text_color=FG_BAD)
        elif kind == "loading":
            self.state_label.configure(text_color=FG_MUTED)
        else:
            self.state_label.configure(text_color=FG_MUTED)

    def _flash_state(self, msg):
        self._set_state(msg, "ok")
        self.after(1200, lambda: self._set_state("Ready.", "idle"))

# ========= Main =========
if __name__ == "__main__":
    ensure_admin_windows()
    app = FirewallVisualizer()
    app.mainloop()
