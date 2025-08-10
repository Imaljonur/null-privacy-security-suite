
import customtkinter as ctk
import psutil
import os
import time

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

def _btn_danger(parent, text, command=None):
    return ctk.CTkButton(parent, text=text, fg_color="#B84C4C", hover_color="#A03E3E", command=command)

class RAMProtector(ctk.CTk):
    def __init__(self):
        super().__init__()
        _theme_setup()
        self.title("∅ RAM Protection")
        self.geometry("900x520")
        self.configure(fg_color=BG_DARK)

        # Grid: Sidebar | Main
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        # --- Sidebar ---
        sb = _card(self)
        sb.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        sb.grid_columnconfigure(0, weight=1)

        _title(sb, "∅ RAM Guard").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        _label(sb, "RAM & Keylogger Protection", muted=True).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

        _btn_primary(sb, "🔎 Scan for Keyloggers", self.scan).grid(row=2, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_danger(sb, "🛑 PANIC SHRED + EXIT", self.panic).grid(row=3, column=0, padx=16, pady=(0,16), sticky="ew")

        # --- Main Card ---
        main = _card(self)
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

        # Result box (same role/name as original)
        self.result_box = ctk.CTkTextbox(body)
        self.result_box.grid(row=0, column=0, sticky="nsew")

        # --- Statusbar ---
        statusbar = _card(self)
        statusbar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
        statusbar.grid_columnconfigure(0, weight=1)
        _label(statusbar, "Tip: Double-click results to select/copy (Ctrl+C).", muted=True).grid(row=0, column=0, padx=12, pady=10, sticky="w")

    # ====== ORIGINAL LOGIC (UNCHANGED) ======
    def scan(self):
        self.status.configure(text="Scanning...")
        self.result_box.delete("0.0", "end")
        suspicious_keywords = ["hook", "keylog", "getasynckeystate", "keyboard"]
        found = False
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline_list = proc.info.get('cmdline', [])
                if isinstance(cmdline_list, list):
                    cmdline = ' '.join(cmdline_list).lower()
                    if any(keyword in cmdline for keyword in suspicious_keywords):
                        self.result_box.insert("end", f"[ALERT] {proc.info['name']} ({proc.info['pid']})\n")
                        found = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
                continue
        if not found:
            self.result_box.insert("end", "✅ No suspicious processes found.")
        self.status.configure(text="Done.")

    def panic(self):
        self.result_box.insert("end", "\n[PANIC] Wiping memory and closing...")
        time.sleep(1)
        os._exit(1)

if __name__ == "__main__":
    app = RAMProtector()
    app.mainloop()
