import customtkinter as ctk
import psutil
import os
import time
import gc
import tempfile
from pathlib import Path

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

def _format_bytes(n: int) -> str:
    step = 1024.0
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < step:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= step
    return f"{n:.1f} PB"

class RAMProtector(ctk.CTk):
    def __init__(self):
        super().__init__()
        _theme_setup()
        self.title("∅ RAM Protection")
        self.geometry("1020x600")
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
        _btn_danger(sb, "🧹 Shred RAM", self.shred).grid(row=3, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_danger(sb, "🧽 Clean Temp Files", self.clean_temp).grid(row=4, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_danger(sb, "🚪 Exit", self.exit_app).grid(row=7, column=0, padx=16, pady=(8,16), sticky="ew")

        # Options
        opt = _card(sb)
        opt.grid(row=5, column=0, padx=16, pady=(8,8), sticky="ew")
        opt.grid_columnconfigure(0, weight=1)
        _label(opt, "Options", muted=True).grid(row=0, column=0, padx=12, pady=(10,4), sticky="w")

        self.var_dryrun = ctk.BooleanVar(value=False)
        self.var_aggr   = ctk.BooleanVar(value=True)

        self.chk_dry = ctk.CTkCheckBox(opt, text="Dry Run (show only)", variable=self.var_dryrun)
        self.chk_aggr = ctk.CTkCheckBox(opt, text="Aggressive (Browsers & Caches)", variable=self.var_aggr)
        self.chk_dry.grid(row=1, column=0, padx=12, pady=(4,2), sticky="w")
        self.chk_aggr.grid(row=2, column=0, padx=12, pady=(0,10), sticky="w")

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

        # Result box
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

    def shred(self):
        # NOTE: True RAM wiping from user-space isn't guaranteed.
        # This attempts to purge typical Python objects and stress-allocate
        # a temporary buffer to reduce remnants in this process.
        self.result_box.insert("end", "\n[SHRED] Attempting to purge sensitive buffers...")
        self.status.configure(text="Shredding...")
        try:
            # Clear known widgets' internal buffers
            self.result_box.delete("0.0", "end")
            gc.collect()
            # Allocate a temporary buffer (~128MB) then overwrite and release
            size_mb = 128
            buf = bytearray(size_mb * 1024 * 1024)
            for i in range(0, len(buf), 4096):
                buf[i:i+4096] = b"\x00" * min(4096, len(buf) - i)
            del buf
            gc.collect()
            self.result_box.insert("end", "\n[SHRED] Local buffers cleared.")
        except Exception as e:
            self.result_box.insert("end", f"\n[SHRED] Error: {e}")
        finally:
            self.status.configure(text="RAM shred attempt complete.")

    # ----------------------
    # Temp/Caches Discovery
    # ----------------------
    def _iter_temp_paths(self, aggressive: bool):
        seen = set()
        paths = []

        # Primary temp dir via Python
        paths.append(Path(tempfile.gettempdir()))

        # OS-specific candidates
        if os.name == "nt":
            for env in ("TEMP", "TMP", "LOCALAPPDATA"):
                p = os.getenv(env)
                if p:
                    if env == "LOCALAPPDATA":
                        paths.append(Path(p) / "Temp")
                    else:
                        paths.append(Path(p))
            if aggressive:
                # Windows caches (may need perms; skip errors)
                local = Path(os.getenv("LOCALAPPDATA", ""))
                roaming = Path(os.getenv("APPDATA", ""))
                # Legacy IE / Edge caches
                paths += [
                    local / "Microsoft" / "Windows" / "INetCache",
                    local / "Microsoft" / "Windows" / "Temporary Internet Files",
                ]
                # Chromium-based caches
                paths += [
                    local / "Google" / "Chrome" / "User Data" / "Default" / "Cache",
                    local / "Google" / "Chrome" / "User Data" / "Default" / "Code Cache",
                    local / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache",
                    local / "Microsoft" / "Edge" / "User Data" / "Default" / "Code Cache",
                    local / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cache",
                ]
                # Firefox profiles caches
                ff_base = roaming / "Mozilla" / "Firefox" / "Profiles"
                if ff_base.exists():
                    for prof in ff_base.glob("*.default*"):
                        paths.append(prof / "cache2")
        else:
            # POSIX
            paths += [Path("/tmp"), Path("/var/tmp")]
            xdg = os.getenv("XDG_CACHE_HOME")
            if xdg:
                paths.append(Path(xdg))
            if aggressive:
                home = Path.home()
                # Common browser caches
                paths += [
                    home / ".cache",
                    home / ".cache" / "mozilla" / "firefox",
                    home / ".cache" / "google-chrome" / "Default" / "Cache",
                    home / ".cache" / "google-chrome" / "Default" / "Code Cache",
                    home / ".cache" / "chromium" / "Default" / "Cache",
                    home / "Library" / "Caches",  # macOS umbrella
                    home / "Library" / "Caches" / "Google" / "Chrome" / "Default" / "Cache",
                    home / "Library" / "Caches" / "Firefox" / "Profiles",
                    Path("/var/cache")
                ]

        # De-duplicate and keep only existing directories
        norm = []
        for p in paths:
            try:
                p = p.resolve()
            except Exception:
                p = Path(str(p))
            if p in seen:
                continue
            seen.add(p)
            if p.exists() and p.is_dir():
                norm.append(p)
        return norm

    def _safe_purge_dir(self, root: Path, dry_run: bool):
        deleted_files = 0
        deleted_bytes = 0
        deleted_dirs = 0
        for base, dirs, files in os.walk(root, topdown=False):
            base_path = Path(base)
            # Skip our own running dir just in case
            try:
                if base_path.samefile(Path.cwd()):
                    continue
            except Exception:
                pass
            # Files
            for name in files:
                fp = base_path / name
                try:
                    size = fp.stat().st_size
                    if dry_run:
                        deleted_files += 1
                        deleted_bytes += size
                    else:
                        try:
                            os.chmod(fp, 0o700)
                        except Exception:
                            pass
                        try:
                            fp.unlink(missing_ok=True)
                            deleted_files += 1
                            deleted_bytes += size
                        except Exception:
                            continue
                except Exception:
                    continue
            # Dirs (remove only if empty and not dry-run)
            if not dry_run:
                for d in dirs:
                    dp = base_path / d
                    try:
                        os.chmod(dp, 0o700)
                        dp.rmdir()
                        deleted_dirs += 1
                    except Exception:
                        continue
        return deleted_files, deleted_dirs, deleted_bytes

    def clean_temp(self):
        dry = bool(self.var_dryrun.get())
        aggr = bool(self.var_aggr.get())

        self.status.configure(text=f"Cleaning temp files (dry={dry}, aggressive={aggr})...")
        self.result_box.insert("end", f"\n[CLEAN] Mode: dry={dry}, aggressive={aggr}")
        self.update_idletasks()

        total_files = total_dirs = total_bytes = 0
        paths = self._iter_temp_paths(aggressive=aggr)
        if not paths:
            self.result_box.insert("end", "\n[CLEAN] No temp directories found.")
            self.status.configure(text="Done.")
            return

        # Show targets
        self.result_box.insert("end", "\n[CLEAN] Targets:")
        for p in paths:
            self.result_box.insert("end", f"\n  - {p}")

        # Purge
        for p in paths:
            try:
                f, d, b = self._safe_purge_dir(p, dry_run=dry)
                total_files += f
                total_dirs += d
                total_bytes += b
            except Exception as e:
                self.result_box.insert("end", f"\n[CLEAN] Skipped {p}: {e}")

        action = "Would remove" if dry else "Removed"
        self.result_box.insert("end", f"\n[CLEAN] {action} {total_files} files, {total_dirs} empty folders, ~{_format_bytes(total_bytes)}.")
        self.status.configure(text="Temp cleanup complete.")

    def exit_app(self):
        self.result_box.insert("end", "\n[EXIT] Closing application...")
        self.update()
        time.sleep(0.5)
        os._exit(0)

if __name__ == "__main__":
    app = RAMProtector()
    app.mainloop()
