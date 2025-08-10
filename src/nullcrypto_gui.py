# nullcrypto_gui_en.py
# ∅ nullcrypto — CustomTkinter GUI (Nullsearch Dark/Green Style)
# Standalone file. No logic changes vs. original core crypto. All UI strings and comments in English.

import os
import base64
from typing import Optional, Tuple
import customtkinter as ctk
from tkinter import filedialog, messagebox

# --- Crypto deps (UNCHANGED LOGIC) ---
import nacl.utils
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)
from argon2.low_level import hash_secret_raw, Type

# ==========================
#  CONSTANTS / FORMAT (UNCHANGED)
# ==========================
SALT_SIZE = 16
NONCE_SIZE = 24
KEY_SIZE = 32
HEADER = b"OC2X"   # format identifier
TEXT_PREFIX = "OCRYPTO:"  # legacy marker (optional)

# ==========================
#  KDF PRESETS (UNCHANGED)
# ==========================
KDF_PRESETS = {
    # (time_cost, memory_cost_kib, parallelism)
    "Standard": (4, 65536, 2),      # ~64 MiB
    "Strong":   (6, 262144, 2),     # ~256 MiB
}
def _get_kdf_params(profile: str) -> Tuple[int,int,int]:
    return KDF_PRESETS.get(profile, KDF_PRESETS["Standard"])

# ==========================
#  KDF (UNCHANGED)
# ==========================
def _derive_key(password: str, salt: bytes, profile: str = "Standard") -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise ValueError("Salt must be 16 bytes")
    t_cost, m_cost, par = _get_kdf_params(profile)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=bytes(salt),
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=par,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )

# ==========================
#  CORE CRYPTO (UNCHANGED)
# ==========================
def encrypt_data(data: bytes, password: str, aad: Optional[bytes] = None, kdf_profile: str = "Standard") -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    if not password:
        raise ValueError("Password must not be empty")
    if aad is not None and not isinstance(aad, (bytes, bytearray)):
        raise TypeError("aad must be bytes or None")
    salt = nacl.utils.random(SALT_SIZE)
    nonce = nacl.utils.random(NONCE_SIZE)
    key = _derive_key(password, salt, kdf_profile)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(bytes(data), aad, nonce, key)
    return HEADER + salt + nonce + ct

def decrypt_data(blob: bytes, password: str, aad: Optional[bytes] = None, kdf_profile: str = "Standard") -> bytes:
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    if not password:
        raise ValueError("Password must not be empty")
    if aad is not None and not isinstance(aad, (bytes, bytearray)):
        raise TypeError("aad must be bytes or None")
    b = bytes(blob)
    if not b.startswith(HEADER):
        raise ValueError("Invalid header (not OC2X)")
    salt = b[4:4+SALT_SIZE]
    nonce = b[4+SALT_SIZE:4+SALT_SIZE+NONCE_SIZE]
    ct = b[4+SALT_SIZE+NONCE_SIZE:]
    key = _derive_key(password, salt, kdf_profile)
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key)

# ==========================
#  TEXT HELPERS (UNCHANGED)
# ==========================
def encrypt_text(text: str, password: str, aad_text: Optional[str] = None, kdf_profile: str = "Standard", add_prefix: bool = False) -> str:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    aad = aad_text.encode("utf-8") if aad_text else None
    blob = encrypt_data(text.encode("utf-8"), password, aad=aad, kdf_profile=kdf_profile)
    b64 = base64.b64encode(blob).decode("ascii")
    return (TEXT_PREFIX + b64) if add_prefix else b64

def decrypt_text(blob_b64: str, password: str, aad_text: Optional[str] = None, kdf_profile: str = "Standard") -> str:
    if not isinstance(blob_b64, str):
        raise TypeError("blob_b64 must be str")
    s = blob_b64.strip()
    if s.startswith(TEXT_PREFIX):
        s = s[len(TEXT_PREFIX):]
    raw = base64.b64decode(s)
    aad = aad_text.encode("utf-8") if aad_text else None
    plain = decrypt_data(raw, password, aad=aad, kdf_profile=kdf_profile)
    return plain.decode("utf-8", errors="strict")

# ==========================
#  FILE HELPERS (UNCHANGED)
# ==========================
def encrypt_file(in_path: str, out_path: Optional[str], password: str, aad_text: Optional[str] = None, kdf_profile: str = "Standard") -> str:
    if not os.path.isfile(in_path):
        raise FileNotFoundError(in_path)
    with open(in_path, "rb") as f:
        data = f.read()
    aad = aad_text.encode("utf-8") if aad_text else None
    blob = encrypt_data(data, password, aad=aad, kdf_profile=kdf_profile)
    if not out_path:
        out_path = in_path + ".scube"
    with open(out_path, "wb") as f:
        f.write(blob)
    return out_path

def decrypt_file(in_path: str, out_path: Optional[str], password: str, aad_text: Optional[str] = None, kdf_profile: str = "Standard") -> str:
    if not os.path.isfile(in_path):
        raise FileNotFoundError(in_path)
    with open(in_path, "rb") as f:
        blob = f.read()
    aad = aad_text.encode("utf-8") if aad_text else None
    plain = decrypt_data(blob, password, aad=aad, kdf_profile=kdf_profile)
    if not out_path:
        if in_path.endswith(".scube"):
            out_path = in_path[:-6]
        else:
            out_path = in_path + ".dec"
    with open(out_path, "wb") as f:
        f.write(plain)
    return out_path

# ==================================================================
#  GUI ONLY — Nullsearch Dark/Green Layout (NO LOGIC CHANGES)
# ==================================================================
# Palette
ACCENT        = "#00FF88"
BG_DARK       = "#0B0F10"
BG_CARD       = "#12171A"
FG_TEXT       = "#D7E0E6"
FG_MUTED      = "#8FA3AD"
FG_OK         = "#7CE38B"
FG_BAD        = "#FF5C7C"
FG_WARN       = "#FFCC66"
BORDER        = "#1D252B"

def _setup_theme():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("green")

def _card(parent, **kwargs):
    opts = dict(fg_color=BG_CARD, corner_radius=14, border_color=BORDER, border_width=1)
    opts.update(kwargs)
    return ctk.CTkFrame(parent, **opts)

def _btn_primary(parent, text, command=None, **kwargs):
    opts = dict(fg_color=ACCENT, text_color="black", command=command, text=text)
    opts.update(kwargs)
    return ctk.CTkButton(parent, **opts)

def _btn_subtle(parent, text, command=None, **kwargs):
    opts = dict(fg_color="#1F2933", hover_color="#25313B", command=command, text=text)
    opts.update(kwargs)
    return ctk.CTkButton(parent, **opts)

def _lbl(parent, text, muted=False, **kwargs):
    color = FG_MUTED if muted else FG_TEXT
    return ctk.CTkLabel(parent, text=text, text_color=color, **kwargs)

def _title(parent, text, **kwargs):
    return ctk.CTkLabel(parent, text=text, text_color=ACCENT, font=ctk.CTkFont(size=20, weight="bold"), **kwargs)

def _metric(parent, label_text, value_text="0"):
    box = ctk.CTkFrame(parent, fg_color=BG_CARD)
    ttl = ctk.CTkLabel(box, text=label_text, text_color=FG_MUTED, font=ctk.CTkFont(size=12))
    val = ctk.CTkLabel(box, text=value_text, text_color=ACCENT, font=ctk.CTkFont(size=18, weight="bold"))
    ttl.pack(anchor="center", pady=(8,0))
    val.pack(anchor="center", pady=(0,8))
    return box, val

class NullCryptoGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        _setup_theme()
        self.title("∅ nullcrypto")
        self.geometry("1040x720")
        self.configure(fg_color=BG_DARK)

        # Layout grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._build_statusbar()

        self.ops = 0; self.oks = 0; self.errs = 0

    # ---------- Sidebar ----------
    def _build_sidebar(self):
        sb = _card(self)
        sb.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        sb.grid_columnconfigure(0, weight=1)

        _title(sb, "∅ nullcrypto").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        _lbl(sb, "XChaCha20-Poly1305 · Argon2id", muted=True).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

        _btn_primary(sb, "Text → Encrypt", self._enc_text).grid(row=2, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "Text → Decrypt", self._dec_text).grid(row=3, column=0, padx=16, pady=(0,16), sticky="ew")

        _btn_subtle(sb, "File → Encrypt (.scube)", self._enc_file).grid(row=4, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "File → Decrypt", self._dec_file).grid(row=5, column=0, padx=16, pady=(0,16), sticky="ew")

        self.status_lbl = _lbl(sb, "Status: idle", muted=True)
        self.status_lbl.grid(row=6, column=0, padx=16, pady=(8,12), sticky="w")

    # ---------- Main ----------
    def _build_main(self):
        main = _card(self)
        main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)

        # Top controls
        top = ctk.CTkFrame(main, fg_color=BG_CARD)
        top.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
        for i in range(8): top.grid_columnconfigure(i, weight=1)

        _lbl(top, "Password").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.pw = ctk.CTkEntry(top, show="*")
        self.pw.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

        _lbl(top, "KDF").grid(row=0, column=2, padx=6, pady=6, sticky="e")
        self.kdf = ctk.CTkComboBox(top, values=list(KDF_PRESETS.keys())); self.kdf.set("Standard")
        self.kdf.grid(row=0, column=3, padx=6, pady=6, sticky="ew")

        _lbl(top, "AAD (optional)").grid(row=0, column=4, padx=6, pady=6, sticky="e")
        self.aad = ctk.CTkEntry(top, placeholder_text="e.g., filename or tag")
        self.aad.grid(row=0, column=5, padx=6, pady=6, sticky="ew")

        self.prefix_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(top, text="Add OCRYPTO: prefix", variable=self.prefix_var).grid(row=0, column=6, padx=6, pady=6, sticky="w")

        # Text IO
        io = ctk.CTkFrame(main, fg_color=BG_CARD)
        io.grid(row=1, column=0, sticky="ew", padx=12, pady=(0,12))
        io.grid_columnconfigure(0, weight=1); io.grid_columnconfigure(1, weight=1)
        _lbl(io, "Input").grid(row=0, column=0, padx=6, pady=(8,2), sticky="w")
        _lbl(io, "Output").grid(row=0, column=1, padx=6, pady=(8,2), sticky="w")
        self.txt_in = ctk.CTkTextbox(io, height=180);  self.txt_in.grid(row=1, column=0, padx=(6,3), pady=4, sticky="ew")
        self.txt_out= ctk.CTkTextbox(io, height=180);  self.txt_out.grid(row=1, column=1, padx=(3,6), pady=4, sticky="ew")

        # File row
        files = ctk.CTkFrame(main, fg_color=BG_CARD)
        files.grid(row=2, column=0, sticky="ew", padx=12, pady=(0,12))
        files.grid_columnconfigure(0, weight=1)
        self.file_in = ctk.CTkEntry(files, placeholder_text="Input file path")
        self.file_in.grid(row=0, column=0, padx=6, pady=6, sticky="ew")
        ctk.CTkButton(files, text="Browse…", command=self._pick_input).grid(row=0, column=1, padx=6, pady=6)

        # Optional log
        self.log_box = ctk.CTkTextbox(main, height=160)
        self.log_box.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0,12))

    # ---------- Statusbar ----------
    def _build_statusbar(self):
        status = _card(self)
        status.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
        status.grid_columnconfigure((0,1,2,3), weight=1)
        self.box_ops,   self.lbl_ops   = _metric(status, "Ops", "0");       self.box_ops.grid(row=0, column=0, sticky="ew", padx=(0,8))
        self.box_ok,    self.lbl_ok    = _metric(status, "OK", "0");        self.box_ok.grid(row=0, column=1, sticky="ew", padx=8)
        self.box_err,   self.lbl_err   = _metric(status, "Errors", "0");    self.box_err.grid(row=0, column=2, sticky="ew", padx=8)
        self.box_state, self.lbl_state = _metric(status, "Status", "idle"); self.box_state.grid(row=0, column=3, sticky="ew", padx=(8,0))

    # ---------- helpers ----------
    def _bump_ops(self): self.ops += 1; self.lbl_ops.configure(text=str(self.ops))
    def _bump_ok(self):  self.oks += 1; self.lbl_ok.configure(text=str(self.oks))
    def _bump_err(self): self.errs += 1; self.lbl_err.configure(text=str(self.errs))

    def _set_state(self, text, kind="idle"):
        self.lbl_state.configure(text=text)
        self.status_lbl.configure(text=f"Status: {text}",
                                  text_color=(FG_MUTED if kind=="idle" else (ACCENT if kind=="ok" else FG_BAD)))

    def _log(self, msg, ok=True):
        try:
            self.log_box.insert("end", msg + "\n"); self.log_box.see("end")
        except Exception:
            pass
        self._bump_ops(); (self._bump_ok() if ok else self._bump_err())

    # ---------- Actions (call UNCHANGED logic) ----------
    def _enc_text(self):
        try:
            pw = self.pw.get().strip()
            inp = self.txt_in.get("1.0","end").rstrip("\n")
            aad = self.aad.get().strip() or None
            profile = self.kdf.get()
            if not pw or not inp: raise ValueError("Enter password and input text")
            out = encrypt_text(inp, pw, aad_text=aad, kdf_profile=profile, add_prefix=self.prefix_var.get())
            self.txt_out.delete("1.0","end"); self.txt_out.insert("end", out)
            self._set_state("Text encrypted", "ok"); self._log("🔐 Text encrypted")
        except Exception as e:
            self._set_state(f"Error: {e}", "error"); self._log(f"❌ {e}", ok=False)

    def _dec_text(self):
        try:
            pw = self.pw.get().strip()
            inp = self.txt_in.get("1.0","end").strip()
            aad = self.aad.get().strip() or None
            profile = self.kdf.get()
            if not pw or not inp: raise ValueError("Enter password and input blob")
            out = decrypt_text(inp, pw, aad_text=aad, kdf_profile=profile)
            self.txt_out.delete("1.0","end"); self.txt_out.insert("end", out)
            self._set_state("Text decrypted", "ok"); self._log("🔓 Text decrypted")
        except Exception as e:
            self._set_state(f"Error: {e}", "error"); self._log(f"❌ {e}", ok=False)

    def _pick_input(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_in.delete(0,"end"); self.file_in.insert(0, path)

    def _enc_file(self):
        try:
            pw = self.pw.get().strip()
            in_path = self.file_in.get().strip()
            aad = self.aad.get().strip() or None
            profile = self.kdf.get()
            if not pw or not in_path: raise ValueError("Pick a file and enter password")
            out_path = in_path + ".scube"
            out = encrypt_file(in_path, out_path, pw, aad_text=aad, kdf_profile=profile)
            self._set_state(f"File encrypted → {out}", "ok"); self._log(f"🔐 File encrypted → {out}")
        except Exception as e:
            self._set_state(f"Error: {e}", "error"); self._log(f"❌ {e}", ok=False)

    def _dec_file(self):
        try:
            pw = self.pw.get().strip()
            in_path = self.file_in.get().strip()
            aad = self.aad.get().strip() or None
            profile = self.kdf.get()
            if not pw or not in_path: raise ValueError("Pick a file and enter password")
            if in_path.lower().endswith(".scube"):
                out_path = in_path[:-6]
            else:
                out_path = in_path + ".dec"
            out = decrypt_file(in_path, out_path, pw, aad_text=aad, kdf_profile=profile)
            self._set_state(f"File decrypted → {out}", "ok"); self._log(f"🔓 File decrypted → {out}")
        except Exception as e:
            self._set_state(f"Error: {e}", "error"); self._log(f"❌ {e}", ok=False)

if __name__ == "__main__":
    app = NullCryptoGUI()
    app.mainloop()
