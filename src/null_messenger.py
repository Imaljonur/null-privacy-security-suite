#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
null_messenger_pfs_full.py — Tor Messenger (Server/Client), no history, gray/green UI
Now with: X25519-ECDH (PFS) pro Verbindung + Session-Key, Key-Rotation, File-Transfer über Session-Key,
Rooms, Admin, Outbox. Grau/Grün UI.
"""

import os, sys, socket, threading, struct, json, time, subprocess, random, base64, uuid
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

import customtkinter as ctk
from tkinter import filedialog, messagebox

# --- Secure Plus helpers ---
from collections import deque
def _rand_pad_b64(min_len=8, max_len=96):
    import os, base64, secrets
    n = secrets.randbelow(max_len - min_len + 1) + min_len
    return base64.b64encode(os.urandom(n)).decode("ascii")

def _jitter_sleep():
    import time, secrets
    time.sleep((50 + secrets.randbelow(251))/1000.0)

class _RateLimiter:
    def __init__(self, max_messages=5, per_seconds=2.0):
        self.max=max_messages; self.win=per_seconds; self.events=deque()
    def allow(self):
        import time
        now=time.monotonic(); cutoff=now-self.win
        while self.events and self.events[0] < cutoff: self.events.popleft()
        if len(self.events) < self.max: self.events.append(now); return True
        return False

class _ReplayGuard:
    def __init__(self, max_ids=512):
        self.seen=deque(); self.idx=set(); self.cap=max_ids
    def add_or_dup(self, mid:str)->bool:
        if not mid: return False
        if mid in self.idx: return True
        self.seen.append(mid); self.idx.add(mid)
        while len(self.seen) > self.cap:
            old=self.seen.popleft(); self.idx.discard(old)
        return False
# --- end helpers ---
# --- Identity / Trust helpers ---
def _fp_hex_ed25519(pubkey_bytes: bytes) -> str:
    import hashlib
    return hashlib.sha256(pubkey_bytes).hexdigest()

def _load_trust_store(app_dir: Path) -> dict:
    p = app_dir / "trusted_servers.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _save_trust_store(app_dir: Path, data: dict) -> None:
    p = app_dir / "trusted_servers.json"
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _load_or_create_server_id(app_dir: Path):
    k = app_dir / "server_ed25519.key"
    if not k.exists():
        sk = Ed25519PrivateKey.generate()
        k.write_bytes(sk.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()))
    else:
        sk = Ed25519PrivateKey.from_private_bytes(k.read_bytes())
    return sk, sk.public_key()
# --- end identity/trust helpers ---


# Crypto (vom User)
try:
    from nullcrypto_gui import encrypt_text, decrypt_text, encrypt_file, decrypt_file, KDF_PRESETS, encrypt_data, decrypt_data
except Exception as e:
    raise RuntimeError("nullcrypto_gui.py fehlt/fehlerhaft. Lege sie in denselben Ordner.") from e

# ECDH
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

THEME = {
    "bg": "#0B0F10",
    "bg_alt": "#12171A",
    "fg": "#D7E0E6",
    "muted": "#8FA3AD",
    "accent": "#00FF88",
    "accent_dark": "#00D477",
    "error": "#FF6B6B",
}
def apply_ctk_theme(ctk, root):
    ctk.set_appearance_mode("dark")
    try: ctk.set_default_color_theme("green")
    except Exception: pass
    root.configure(fg_color=THEME["bg"])

if sys.platform == "win32":
    try:
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

APP_DIR = Path(os.path.abspath(os.path.dirname(__file__)))
CLIENT_ID_FILE = APP_DIR / "client_id.txt"
TOR_DIR = APP_DIR / "tor"
TOR_BIN = TOR_DIR / ("tor.exe" if os.name == "nt" else "tor")
TOR_DATA_DIR = TOR_DIR / "data" / "tor"
TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)

# ===== Framing =====
def send_json(sock: socket.socket, obj: Dict[str, Any]):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)
def recvall(sock: socket.socket, n: int) -> bytes:
    data=b""
    while len(data) < n:
        chunk = sock.recv(n-len(data))
        if not chunk: return b""
        data += chunk
    return data
def recv_json(sock: socket.socket) -> Dict[str, Any]:
    hdr = recvall(sock, 4)
    if not hdr: raise ConnectionError("Connection closed")
    (length,) = struct.unpack("!I", hdr)
    data = recvall(sock, length)
    return json.loads(data.decode("utf-8"))

# Client-ID persistent
def _get_client_id() -> str:
    try:
        if CLIENT_ID_FILE.exists():
            cid = CLIENT_ID_FILE.read_text(encoding="utf-8").strip()
            if cid: return cid
        cid = str(uuid.uuid4()); CLIENT_ID_FILE.write_text(cid, encoding="utf-8"); return cid
    except Exception:
        return str(uuid.uuid4())

# Tor helpers
def _wait_port_open(host: str, port: int, timeout: int = 60) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False
def _write_torrc_server(chat_port: int, file_port: int) -> Path:
    torrc = TOR_DATA_DIR / "torrc"
    hs_chat = TOR_DATA_DIR / "hs_chat"; hs_chat.mkdir(parents=True, exist_ok=True)
    hs_file = TOR_DATA_DIR / "hs_file"; hs_file.mkdir(parents=True, exist_ok=True)
    torrc.write_text(
        f"DataDirectory {TOR_DATA_DIR.as_posix()}\n"
        f"Log notice file {(TOR_DATA_DIR/'tor_server.log').as_posix()}\n"
        f"SocksPort 0\nControlPort 0\n"
        f"HiddenServiceDir {hs_chat.as_posix()}\nHiddenServiceVersion 3\nHiddenServicePort 80 127.0.0.1:{chat_port}\n"
        f"HiddenServiceDir {hs_file.as_posix()}\nHiddenServiceVersion 3\nHiddenServicePort 443 127.0.0.1:{file_port}\n"
        f"ExitPolicy reject *:*\n", encoding="utf-8"
    ); return torrc
def _write_torrc_client(socks_port: int) -> Path:
    torrc = TOR_DATA_DIR / "torrc_client"
    torrc.write_text(
        f"DataDirectory {TOR_DATA_DIR.as_posix()}\n"
        f"Log notice file {(TOR_DATA_DIR/'tor_client.log').as_posix()}\n"
        f"SocksPort {socks_port}\nControlPort 0\nExitPolicy reject *:*\n", encoding="utf-8"
    ); return torrc
def _start_tor(torrc_path: Path) -> subprocess.Popen:
    if not TOR_BIN.exists(): raise FileNotFoundError(f"Tor not found: {TOR_BIN}")
    return subprocess.Popen([str(TOR_BIN), "-f", str(torrc_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
def _wait_for_onions() -> Dict[str,str]:
    t0=time.time(); hs={"chat": TOR_DATA_DIR/"hs_chat", "file": TOR_DATA_DIR/"hs_file"}
    while time.time()-t0 < 120:
        hostnames={}; ok=True
        for k,d in hs.items():
            f=d/"hostname"
            if f.exists(): hostnames[k]=f.read_text(encoding="utf-8").strip()
            else: ok=False
        if ok: return hostnames
        time.sleep(0.2)
    raise TimeoutError("Hidden Service hostname was not created (Timeout).")
def _pick_free_port(start=9150, end=9700) -> int:
    for _ in range(100):
        p=random.randint(start,end)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try: s.bind(("127.0.0.1", p)); return p
            except OSError: continue
    return 9150
def _connect_via_tor(onion: str, socks_host: str, socks_port: int) -> socket.socket:
    import socks as pysocks
    s=pysocks.socksocket(); s.set_proxy(pysocks.SOCKS5, socks_host, socks_port); s.settimeout(30); s.connect((onion,80))
    return s

# Local server
def start_local_server(port: int, on_client):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(5)
    def accept_loop():
        while True:
            try: c, addr = s.accept()
            except OSError: break
            threading.Thread(target=on_client, args=(c,), daemon=True).start()
    threading.Thread(target=accept_loop, daemon=True).start(); return s

class NullMessenger(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("∅ null_messenger"); self.geometry("1000x700"); apply_ctk_theme(ctk, self)

        # State
        self.role=None; self.tor_proc=None; self.socks_port=None
        self.chat_server=None; self.file_server=None
        self.active_sock=None; self.active_onion=None
        self.clients=set(); self.clients_map={}; self.clients_id_map={}
        self.nick_to_id={}; self.bans={}
        self.outbox=[]
        # Trust store / verification
        self.trusted = _load_trust_store(APP_DIR)
        self.server_verified = False
        self.server_sid_fp = None
        self.server_sid_pub = None
        # Colors
        self.my_color = "#00aa00"; self.colors_map = {}

        # Secure Plus state
        self._rate = _RateLimiter(5, 2.0)
        self._replay = _ReplayGuard(512)
        self.password=""; self.kdf_profile="Standard"; self.room="default"
        # PFS
        self.session_password=None            # client-side
        self.sessions={}                      # server: sock -> {'sess_pw':str,'count':0,'rekey_priv':opt}
        self.ROTATE_EVERY=100

        self.role_dialog()

        # Layout
        self.grid_rowconfigure(0, weight=1); self.grid_columnconfigure(1, weight=1)
        self.sidebar = ctk.CTkFrame(self, fg_color=THEME["bg_alt"]); self.sidebar.grid(row=0, column=0, sticky="nsew", padx=(8,4), pady=8)
        self.sidebar.grid_rowconfigure(6, weight=1)
        ctk.CTkLabel(self.sidebar, text="Mode", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10,4))
        self.lbl_mode = ctk.CTkLabel(self.sidebar, text=self.role or "—"); self.lbl_mode.pack(anchor="w", padx=10)
        ctk.CTkLabel(self.sidebar, text="Password (KDF)", text_color=THEME["muted"]).pack(anchor="w", padx=10, pady=(10,4))
        self.entry_pw = ctk.CTkEntry(self.sidebar, show="*"); self.entry_pw.pack(fill="x", padx=10)
        ctk.CTkLabel(self.sidebar, text="KDF Profile", text_color=THEME["muted"]).pack(anchor="w", padx=10, pady=(10,4))
        self.kdf_combo = ctk.CTkComboBox(self.sidebar, values=list(KDF_PRESETS.keys())); self.kdf_combo.set("Standard"); self.kdf_combo.pack(fill="x", padx=10)
        ctk.CTkLabel(self.sidebar, text="Nickname", text_color=THEME["muted"]).pack(anchor="w", padx=10, pady=(10,4))
        self.entry_nick = ctk.CTkEntry(self.sidebar); self.entry_nick.pack(fill="x", padx=10); self.entry_nick.insert(0,"ich")
        ctk.CTkLabel(self.sidebar, text="Room", text_color=THEME["muted"]).pack(anchor="w", padx=10, pady=(10,4))
        self.entry_room = ctk.CTkEntry(self.sidebar); self.entry_room.pack(fill="x", padx=10); self.entry_room.insert(0,"default")
        self.btn_action = ctk.CTkButton(self.sidebar, text="Start", command=self.start_action); self.btn_action.pack(fill="x", padx=10, pady=(12,6))
        ctk.CTkLabel(self.sidebar, text="Onion (Client target / Host own below)", text_color=THEME["muted"]).pack(anchor="w", padx=10, pady=(12,4))
        self.entry_onion = ctk.CTkEntry(self.sidebar, placeholder_text="xxxx.onion (Client)"); self.entry_onion.pack(fill="x", padx=10)
        self.status = ctk.CTkLabel(self.sidebar, text="Ready.", text_color=THEME["muted"]); self.status.pack(anchor="w", padx=10, pady=(8,10))

        self.main = ctk.CTkFrame(self, fg_color=THEME["bg_alt"]); self.main.grid(row=0, column=1, sticky="nsew", padx=(4,8), pady=8)
        self.main.grid_rowconfigure(1, weight=1); self.main.grid_columnconfigure(0, weight=1)
        self.header = ctk.CTkLabel(self.main, text="No chat", anchor="w"); self.header.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self.chat_box = ctk.CTkTextbox(self.main, fg_color=THEME["bg"], text_color=THEME["fg"]); self.chat_box.configure(state="disabled")
        self.chat_box.grid(row=1, column=0, sticky="nsew", padx=10)
        bottom = ctk.CTkFrame(self.main, fg_color=THEME["bg_alt"]); bottom.grid(row=2, column=0, sticky="ew", padx=10, pady=10); bottom.grid_columnconfigure(0, weight=1)
        self.entry = ctk.CTkEntry(bottom, placeholder_text="Message…"); self.entry.grid(row=0, column=0, sticky="ew", padx=(0,8)); self.entry.bind("<Return>", lambda e: self.send_msg())
        self.btn_file = ctk.CTkButton(bottom, text="📎", width=44, command=self.send_file); self.btn_file.grid(row=0, column=1, padx=(0,8))
        self.btn_send = ctk.CTkButton(bottom, text="Send", command=self.send_msg); self.btn_send.grid(row=0, column=2)
        # --- NullCrypto (manuell) ---
        nc_row = ctk.CTkFrame(self.main, fg_color=THEME["bg_alt"])
        nc_row.grid(row=3, column=0, sticky="ew", padx=10, pady=(0,10))
        nc_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(nc_row, text="NullCrypto PW").grid(row=0, column=0, padx=(4,6))
        self.nc_pw = ctk.CTkEntry(nc_row, show="*")
        self.nc_pw.grid(row=0, column=1, sticky="ew", padx=(0,8))
        ctk.CTkButton(nc_row, text="🔐 NC-Encrypt (Eingabe)", command=self._nc_encrypt_entry).grid(row=0, column=2, padx=4)
        ctk.CTkButton(nc_row, text="🔓 NC-Decrypt (Eingabe)", command=self._nc_decrypt_entry).grid(row=0, column=3, padx=4)
        ctk.CTkButton(nc_row, text="🔐 NC-Encrypt File", command=self._nc_encrypt_file_dialog).grid(row=0, column=4, padx=4)
        ctk.CTkButton(nc_row, text="🔓 NC-Decrypt File", command=self._nc_decrypt_file_dialog).grid(row=0, column=5, padx=4)
        self.set_connected_state(False)

    def role_dialog(self):
        dlg = ctk.CTkInputDialog(text="Choose mode: server or client", title="Start mode")
        val = (dlg.get_input() or "").strip().lower()
        if val not in ("server", "client"): val = "server"
        self.role = val

    def log(self, line: str):
        self.chat_box.configure(state="normal"); self.chat_box.insert("end", line + "\n"); self.chat_box.configure(state="disabled"); self.chat_box.see("end")
    
    def log_colored(self, line: str, color: str | None = None):
        try:
            self.chat_box.configure(state="normal")
            if color and isinstance(color, str) and color.startswith("#"):
                tag = f"fg_{color}"
                try:
                    self.chat_box.tag_config(tag, foreground=color)
                except Exception:
                    try:
                        # Fallback: Tkinter Text API
                        self.chat_box.tag_configure(tag, foreground=color)
                    except Exception:
                        tag = None
                if tag:
                    self.chat_box.insert("end", line + "\n", tag)
                else:
                    self.chat_box.insert("end", line + "\n")
            else:
                self.chat_box.insert("end", line + "\n")
            self.chat_box.configure(state="disabled"); self.chat_box.see("end")
        except Exception:
            # Fallback to plain log
            try:
                self.log(line)
            except Exception:
                pass
    def set_status(self, t: str): self.status.configure(text=t)
    
    def set_connected_state(self, enabled: bool):
        state="normal" if enabled else "disabled"
        for w in (self.entry, self.btn_send, self.btn_file):
            try: w.configure(state=state)
            except Exception: pass

    def _derive_session_password(self, shared_secret: bytes) -> str:
        # Base64 der ECDH-Secret als "Passwort" für nullcrypto-KDF
        return base64.b64encode(shared_secret).decode("ascii")

    def start_action(self):
        self.password = self.entry_pw.get().strip()
        self.kdf_profile = self.kdf_combo.get()
        self.room = (self.entry_room.get().strip() or "default")
        if not self.password:
            messagebox.showinfo("Note", "Please set a password (for E2E crypto)."); return
        if self.role == "server": self.start_server()
        else: self.start_client()

    # Server
    def start_server(self):
        self.chat_server = start_local_server(18211, self._handle_chat_client)
        self.file_server = start_local_server(18212, self._handle_file_client)
        self.set_status("Local servers running. Starting Tor (HS)…")
        torrc = _write_torrc_server(18211, 18212)
        try:
            if self.tor_proc and self.tor_proc.poll() is None: self.tor_proc.terminate()
            self.tor_proc = _start_tor(torrc)
        except Exception as e:
            messagebox.showerror("Tor Error", str(e)); return
        try:
            hs = _wait_for_onions()
            self.active_onion = hs["chat"]
            self.header.configure(text=f"Host aktiv: {hs['chat']}"); self.log(f"Your Chat-Onion: {hs['chat']}"); self.log(f"Your File-Onion: {hs['file']}")
            self.set_status("Hidden services running."); self.set_connected_state(True)
        except Exception as e:
            messagebox.showerror("HS Error", str(e)); self.set_status("Hidden service error.")

    def _handle_chat_client(self, sock: socket.socket):
        addr = sock.getpeername(); self.log(f"[+] Chat verbunden von {addr}")
        # ECDH: zuerst keyex des Clients empfangen
        try:
            first = recv_json(sock)
            if first.get("type") != "keyex":
                self.log("[x] Erwartete keyex zuerst. Connection closed."); sock.close(); return
            try:
                cli_pub_bytes = base64.b64decode(first.get("pubkey",""))
                cli_pub = x25519.X25519PublicKey.from_public_bytes(cli_pub_bytes)
            except Exception as e:
                self.log(f"[x] Invalid client public key: {e}"); sock.close(); return
            # Server-Keys erzeugen
            srv_priv = x25519.X25519PrivateKey.generate()
            srv_pub = srv_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            # Session ableiten
            shared = srv_priv.exchange(cli_pub)
            sess_pw = self._derive_session_password(shared)
            self.sessions[sock] = {"sess_pw": sess_pw, "count": 0, "rekey_priv": None}
            # Server-PubKey senden
            sid_pub_bytes = self.server_id_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            nonce = os.urandom(16)
            bundle = json.dumps({
                "eph": base64.b64encode(srv_pub).decode("ascii"),
                "room": self.room,
                "nonce": base64.b64encode(nonce).decode("ascii")
            }).encode("utf-8")
            sig = self.server_id_priv.sign(bundle)
            send_json(sock, {"type":"keyex","pubkey": base64.b64encode(srv_pub).decode("ascii"), "sid_pub": base64.b64encode(sid_pub_bytes).decode("ascii"), "sig": base64.b64encode(sig).decode("ascii"), "bundle": base64.b64encode(bundle).decode("ascii")})
            self.set_status("Session-Key aktiv")
        except Exception as e:
            self.log(f"[x] Key-exchange error: {e}"); 
            try: sock.close()
            except Exception: pass
            return

        # Hello/Room/Ban
        try:
            hello = recv_json(sock)
            if hello.get("type") != "hello":
                self.log("[x] Handshake 'hello' missing."); sock.close(); return
            nick = str(hello.get("nick") or "Peer")[:32]
            room = str(hello.get("room") or "default")[:64]
            client_id = str(hello.get("client_id") or "")[:64]
            if room != self.room:
                self.log(f"[x] Client in anderem Room: {room} (Server-Room: {self.room}) — trenne."); sock.close(); return
            # Bans
            now=time.time(); until=self.bans.get(client_id, None)
            if until is None and client_id in self.bans:
                self.log(f"[x] Banned client (permanent): {client_id}"); sock.close(); return
            if isinstance(until,(int,float)) and now < until:
                self.log(f"[x] Banned client ({int(until-now)}s rest): {client_id}"); sock.close(); return
            # Accept
            self.clients.add(sock); self.clients_map[sock]=nick; self.clients_id_map[sock]=client_id; self.nick_to_id[nick]=client_id
            self.set_connected_state(True); self.header.configure(text=f"Connected with {nick}")
            # Outbox flush (mit Session-Key)
            if self.outbox:
                sess = self.sessions.get(sock)
                if sess:
                    for item in list(self.outbox):
                        try:
                            sess["count"] = int(sess.get("count",0)) + 1
                            cnt = sess["count"]
                            pad = _rand_pad_b64()
                            payload = json.dumps({"t": item["text"], "pad": pad})
                            peer_cid = self.clients_id_map.get(sock, "")
                            aad = self._aad_for("msg", counter=cnt, peer_client_id=peer_cid)
                            blob_b64 = encrypt_text(payload, sess["sess_pw"], aad_text=aad, kdf_profile=self.kdf_profile, add_prefix=False)
                            mid = base64.b64encode(os.urandom(12)).decode("ascii")
                            send_json(sock, {"type":"msg","blob": blob_b64, "nick": item["nick"], "mid": mid, "ctr": cnt, "color": self.my_color})
                            sess["count"] += 1
                        except Exception: pass
                    self.outbox.clear(); self.set_status("Delivered: Outbox flushed")
        except Exception:
            try: sock.close()
            except Exception: pass
            return

        # Receive loop
        try:
            while True:
                obj = recv_json(sock)
                t = obj.get("type")
                if t == "color":
                    val = str(obj.get("value") or "").strip()
                    if len(val) in (4,7) and val.startswith("#") and all(c in "0123456789abcdefABCDEF#" for c in val):
                        self.colors_map[sock] = val
                        self.set_status(f"Color from {self.clients_map.get(sock) or 'Peer'} = {val}")
                    else:
                        self.set_status("Invalid color message ignored")
                    continue
                if t == "msg":
                    sess = self.sessions.get(sock)
                    if not sess: self.log("[x] Message without session key ignored."); continue
                    blob_b64 = obj.get("blob","")
                    mid = obj.get("mid","")
                    if self._replay.add_or_dup(mid):
                        self.log("[i] Replay dropped."); continue
                    ctr = int(obj.get("ctr",0))
                    peer_cid = self.clients_id_map.get(sock, "")
                    aad = self._aad_for("msg", counter=ctr, peer_client_id=peer_cid)
                    try:
                        plain = decrypt_text(blob_b64, sess["sess_pw"], aad_text=aad, kdf_profile=self.kdf_profile)
                        try:
                            jo = json.loads(plain)
                            text = jo.get("t", plain)
                        except Exception:
                            text = plain
                    except Exception as e:
                        text = "[Decrypt error: {}]".format(e)
                    nick_in = self.clients_map.get(sock) or obj.get("nick") or "Peer"
                    self.log(f"{{nick_in}}: {{text}}")
                elif t == "file":

                    # Datei-Stream über Chat-Socket (verschlüsselt per Session-Key)

                    sess = self.sessions.get(sock)

                    if not sess: self.log("[x] File without session key ignored."); continue

                    name = obj.get("name","file.bin"); size = int(obj.get("size",0))

                    chunks=[]; remaining=size

                    while remaining>0:

                        chunk = sock.recv(min(65536, remaining))

                        if not chunk: break

                        chunks.append(chunk); remaining -= len(chunk)

                    enc = b"".join(chunks)

                    outdir = filedialog.askdirectory(title="Choose folder to save file")

                    if not outdir: self.log("[x] Save cancelled."); continue

                    out_path = os.path.join(outdir, name)

                    try:

                        mid = obj.get("mid","")

                        if self._replay.add_or_dup(mid):

                            self.log("[i] Replay file dropped.");

                            # trotzdem Stream leeren (schon gelesen)

                            continue

                        ctr = int(obj.get("ctr",0))

                        peer_cid = self.clients_id_map.get(sock, "")

                        aad_s = self._aad_for("file", name=name, size=size, counter=ctr, peer_client_id=peer_cid).encode("utf-8")

                        plain = decrypt_data(enc, sess["sess_pw"], aad=aad_s, kdf_profile=self.kdf_profile)

                        with open(out_path, "wb") as f: f.write(plain)

                        self.log(f"[✓] File saved: {out_path}")

                    except Exception as e:

                        self.log("[x] File decryption failed: {}".format(e))

                    # Client initiiert Rotation
                    try:
                        peer_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(obj.get("pubkey","")))
                        priv = x25519.X25519PrivateKey.generate()
                        pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                        shared = priv.exchange(peer_pub)
                        sess = self.sessions.get(sock)
                        if sess: 
                            sess["sess_pw"] = self._derive_session_password(shared)
                            sess["count"] = 0
                        send_json(sock, {"type":"rekey_ack","pubkey": base64.b64encode(pub).decode("ascii")})
                        self.set_status("Session-Key aktiv (rotated)")
                    except Exception as e:
                        self.log(f"[x] Rekey error: {e}")
                elif t == "rekey_ack":
                    # Antwort auf vom Server initiiertes Rekey
                    sess = self.sessions.get(sock)
                    if not sess or not sess.get("rekey_priv"): continue
                    try:
                        peer_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(obj.get("pubkey","")))
                        shared = sess["rekey_priv"].exchange(peer_pub)
                        sess["sess_pw"] = self._derive_session_password(shared)
                        sess["rekey_priv"] = None
                        sess["count"] = 0
                        self.set_status("Session-Key aktiv (rotated)")
                    except Exception as e:
                        self.log(f"[x] Rekey-ack error: {e}")
                else:
                    self.log(f"[?] Unknown packet: {obj}")
        except Exception:
            pass
        finally:
            try:
                self.clients.discard(sock); self.clients_map.pop(sock, None); self.clients_id_map.pop(sock, None); self.sessions.pop(sock, None); sock.close()
            except Exception: pass
            self.log("[-] Chat disconnected.")

    def _handle_file_client(self, sock: socket.socket):
        # Nicht mehr genutzt: Dateiübertragung läuft über Chat-Socket mit Session-Key
        try: sock.close()
        except Exception: pass

    # Client
    def start_client(self):
        onion = self.entry_onion.get().strip()
        if not onion.endswith(".onion"):
            messagebox.showinfo("Note", "Please enter a valid .onion address."); return
        self.set_status("Starting Tor (client)…"); self.set_connected_state(False)
        self.socks_port = _pick_free_port(); torrc = _write_torrc_client(self.socks_port)
        try:
            if self.tor_proc and self.tor_proc.poll() is None: self.tor_proc.terminate()
            self.tor_proc = _start_tor(torrc)
        except Exception as e:
            messagebox.showerror("Tor Error", str(e)); return
        self.set_status(f"Waiting for Tor SOCKS {self.socks_port}…")
        if not _wait_port_open("127.0.0.1", int(self.socks_port), timeout=60):
            messagebox.showerror("Tor Error", f"SOCKS-Port {self.socks_port} was not ready in 60s."); return
        self.set_status("Connecting to Onion…")
        start_t=time.time(); last_err=None
        while time.time()-start_t < 60:
            try:
                s = _connect_via_tor(onion, "127.0.0.1", int(self.socks_port))
                self.active_sock = s; self.active_onion = onion
                self.header.configure(text=f"Connected with {onion}")
                self.set_status(f"Client über SOCKS {self.socks_port}")
                # ECDH keyex: Client -> Server
                cli_priv = x25519.X25519PrivateKey.generate()
                cli_pub = cli_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                send_json(self.active_sock, {"type":"keyex","pubkey": base64.b64encode(cli_pub).decode("ascii")})
                self.set_status("Warte auf Schlüsselaustausch…")
                
                resp = recv_json(self.active_sock)
                if resp.get("type") != "keyex":
                    messagebox.showerror("Handshake error", "Server sandte kein keyex."); return
                try:
                    srv_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(resp.get("pubkey","")))
                    # Signed server identity (optional verification)
                    sid_pub_b64 = resp.get("sid_pub"); sig_b64 = resp.get("sig"); bundle_b64 = resp.get("bundle")
                    self.server_verified = False; self.server_sid_pub = None; self.server_sid_fp = None
                    if sid_pub_b64 and sig_b64 and bundle_b64:
                        try:
                            sid_pub_bytes = base64.b64decode(sid_pub_b64)
                            sig = base64.b64decode(sig_b64)
                            bundle = base64.b64decode(bundle_b64)
                            sid_pub = Ed25519PublicKey.from_public_bytes(sid_pub_bytes)
                            sid_pub.verify(sig, bundle)  # raises if invalid
                            self.server_sid_pub = sid_pub
                            self.server_sid_fp = _fp_hex_ed25519(sid_pub_bytes)
                            if self.server_sid_fp in self.trusted:
                                self.server_verified = True
                            self.set_status("Session-Key aktiv ({})".format("verifiziert" if self.server_verified else "UNVERIF."))
                        except Exception as e:
                            self.set_status(f"Warning: signature verification failed: {e}")
                except Exception as e:
                    messagebox.showerror("Handshake error", f"Invalid server public key: {e}"); return
                shared = cli_priv.exchange(srv_pub)
                self.session_password = self._derive_session_password(shared)
                self.set_status("Session-Key aktiv")
                # hello
                nick = self.entry_nick.get().strip() or "ich"
                send_json(self.active_sock, {"type":"hello","nick": nick, "room": self.room, "version": 1, "client_id": _get_client_id()})
                self.set_connected_state(True)
                # Start Receiver-Thread für Rekey-Acks (und evtl. Server-Nachrichten in Zukunft)
                threading.Thread(target=self._client_recv_loop, daemon=True).start()
                return
            except Exception as e:
                last_err=e; time.sleep(1.0)
        messagebox.showerror("Connection failed", f"Could not connect in 60s: {last_err}")

    def _client_recv_loop(self):
        s = self.active_sock
        if not s: return
        try:
            while True:
                obj = recv_json(s)
                t = obj.get("type")
                if t == "rekey":
                    # Server initiiert Rotation
                    try:
                        peer_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(obj.get("pubkey","")))
                        priv = x25519.X25519PrivateKey.generate()
                        pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                        shared = priv.exchange(peer_pub)
                        self.session_password = self._derive_session_password(shared)
                        send_json(s, {"type":"rekey_ack","pubkey": base64.b64encode(pub).decode("ascii")})
                        self.set_status("Session-Key aktiv (rotated)")
                    except Exception as e:
                        self.set_status(f"Rekey error: {e}")
                elif t == "rekey_ack":
                    # Antwort auf vom Client initiiertes Rekey
                    priv = getattr(self, "_rekey_priv", None)
                    if not priv: continue
                    try:
                        peer_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(obj.get("pubkey","")))
                        shared = priv.exchange(peer_pub)
                        self.session_password = self._derive_session_password(shared)
                        self._rekey_priv = None
                        self.set_status("Session-Key aktiv (rotated)")
                    except Exception as e:
                        self.set_status(f"Rekey-ack error: {e}")
                elif t == "sys":
                    # Systemnachrichten
                    self.log(f"[sys] {obj.get('msg','')}")
                else:
                    # aktuell ignorieren (Server sendet keine Chat-Echos)
                    pass
        except Exception:
            pass

    def _client_initiate_rekey(self):
        if not self.active_sock: return
        try:
            self.set_status("Renewing key…")
            priv = x25519.X25519PrivateKey.generate()
            pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            self._rekey_priv = priv
            send_json(self.active_sock, {"type":"rekey","pubkey": base64.b64encode(pub).decode("ascii")})
        except Exception as e:
            self.set_status(f"Rekey start failed: {e}")

    def _aad_for(self, kind:str, name:str=None, size:int=None, counter:int=0, peer_client_id:str="") -> str:
        # room|nick|client_id|counter[|file|name|size]
        nick = (self.entry_nick.get().strip() or "ich")
        parts = [str(self.room), str(nick), str(peer_client_id), str(counter)]
        if kind=="file" and name is not None and size is not None:
            parts += ["file", str(name), str(size)]
        return "|".join(parts)

    # Send
    def send_msg(self):
        text = self.entry.get().strip()
        if not text: return
        nick = self.entry_nick.get().strip() or "ich"

        # Admin (server)
        if text.lower().startswith("/fingerprint"):
            if self.role == "server":
                try:
                    if hasattr(self, "server_id_pub"):
                        fp = _fp_hex_ed25519(self.server_id_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
                        self.log(f"[Server-Fingerprint] {fp}")
                    else:
                        # try to load
                        self.server_id_priv, self.server_id_pub = _load_or_create_server_id(APP_DIR)
                        fp = _fp_hex_ed25519(self.server_id_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
                        self.log(f"[Server-Fingerprint] {fp}")
                except Exception as e:
                    self.set_status(f"Fingerprint Fehler: {e}")
            else:
                if self.server_sid_fp:
                    self.log(f"[Server-Fingerprint] {self.server_sid_fp}")
                else:
                    self.set_status("Kein Server-Fingerprint (noch nicht verbunden?)")
            self.entry.delete(0,"end"); return
        if text.lower().startswith("/trust "):
            val = (text.split(" ",1)[1] if " " in text else "").strip().lower()
            if len(val)==64 and all(c in "0123456789abcdef" for c in val):
                self.trusted[val] = True
                try:
                    _save_trust_store(APP_DIR, self.trusted)
                    self.set_status(f"Trusted: {val[:16]}…")
                    if self.server_sid_fp == val:
                        self.server_verified = True; self.set_status("Session-Key aktiv (verifiziert)")
                except Exception as e:
                    self.set_status(f"Trust speichern fehlgeschlagen: {e}")
            else:
                self.set_status("Bitte 64-stelligen Hex-Fingerprint angeben.")
            self.entry.delete(0,"end"); return
        if text.lower().startswith("/color "):
            val = text.split(" ",1)[1].strip()
            if not (len(val) in (4,7) and val.startswith("#") and all(c in "0123456789abcdefABCDEF#" for c in val)):
                self.set_status("Ungültige Farbe. Nutze z.B. #666666 oder #6a6")
                self.entry.delete(0,"end"); return
            self.my_color = val
            # an Server melden, falls client
            try:
                if self.role == "client" and self.active_sock:
                    send_json(self.active_sock, {"type":"color","value": val})
            except Exception:
                pass
            self.set_status(f"Farbe gesetzt auf {val}"); self.entry.delete(0,"end"); return
        
        if self.role == "server" and text.startswith("/"):
            parts = text.split(); cmd = parts[0].lower(); a1=parts[1] if len(parts)>1 else None; a2=parts[2] if len(parts)>2 else None
            if cmd == "/fingerprint":
                try:
                    fp = _fp_hex_ed25519(self.server_id_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
                    self.log(f"[Server-Fingerprint] {fp}")
                except Exception as e:
                    self.set_status(f"Fingerprint Fehler: {e}")
                self.entry.delete(0,"end"); return
            if cmd == "/users":
                try: names=[self.clients_map.get(s,"Peer") for s in self.clients]; self.set_status("Users: " + (", ".join(names) if names else "Keine Nutzer"))
                except Exception: pass; self.entry.delete(0,"end"); return
            if cmd == "/bans":
                try:
                    now=time.time(); items=[]
                    for cid, until in self.bans.items():
                        if until is None: items.append(f"{cid}: forever")
                        else: items.append(f"{cid}: {int(max(0, until-now))}s")
                    self.set_status("Bans: " + (", ".join(items) if items else "keine"))
                except Exception: pass; self.entry.delete(0,"end"); return
            if cmd == "/ban" and a1:
                cid = self.nick_to_id.get(a1, a1)
                if not a2: self.set_status('Usage: /ban <nick|id> <minutes|forever>'); self.entry.delete(0,"end"); return
                if a2.lower()=="forever": self.bans[cid]=None; self.set_status(f"Gebannt: {cid} forever")
                else:
                    try: minutes=int(a2); self.bans[cid]=time.time()+minutes*60; self.set_status(f"Gebannt: {cid} für {minutes} min")
                    except Exception: self.set_status('Ungültige Dauer. Zahl oder "forever".'); self.entry.delete(0,"end"); return
                to_drop=[s for s,idv in self.clients_id_map.items() if idv==cid]
                for s in to_drop:
                    try: self.clients.discard(s); self.clients_map.pop(s,None); self.clients_id_map.pop(s,None); self.sessions.pop(s,None); s.close()
                    except Exception: pass
                self.entry.delete(0,"end"); return
            if cmd == "/unban" and a1:
                cid=self.nick_to_id.get(a1,a1)
                if cid in self.bans: self.bans.pop(cid,None); self.set_status(f"Unbanned: {cid}")
                else: self.set_status("Nicht gebannt.")
                self.entry.delete(0,"end"); return
            self.set_status("Unbekannt: /users, /bans, /ban, /unban"); self.entry.delete(0,"end"); return

        try:
            if self.role == "server":
                if not self.clients:
                    self.outbox.append({"nick": nick, "text": text}); self.log_colored(f"{nick}: {text}", self.my_color); self.entry.delete(0,"end"); return
                dead=[]
                for c in list(self.clients):
                    try:
                        sess = self.sessions.get(c)
                        if not sess: continue
                        # Rotation falls nötig
                        if sess["count"] >= self.ROTATE_EVERY:
                            self.set_status("Renewing key…")
                            priv = x25519.X25519PrivateKey.generate()
                            pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                            sess["rekey_priv"] = priv
                            send_json(c, {"type":"rekey","pubkey": base64.b64encode(pub).decode("ascii")})
                            sess["count"] = 0
                        # Send
                        mid = base64.b64encode(os.urandom(12)).decode("ascii")
                        if not self._rate.allow():
                            continue
                        sess["count"] = int(sess.get("count",0))
                        cnt = sess["count"] + 1
                        pad = _rand_pad_b64()
                        payload = json.dumps({"t": text, "pad": pad})
                        peer_cid = self.clients_id_map.get(c, "")
                        aad = self._aad_for("msg", counter=cnt, peer_client_id=peer_cid)
                        _jitter_sleep()
                        blob_b64 = encrypt_text(payload, sess["sess_pw"], aad_text=aad, kdf_profile=self.kdf_profile, add_prefix=False)
                        sess["count"] = cnt
                        send_json(c, {"type":"msg","blob": blob_b64, "nick": nick, "mid": mid, "ctr": cnt, "color": self.my_color})
                        sess["count"] += 1
                    except Exception:
                        dead.append(c)
                for d in dead:
                    try: self.clients.discard(d); self.clients_map.pop(d,None); self.clients_id_map.pop(d,None); self.sessions.pop(d,None); d.close()
                    except Exception: pass
                self.log_colored(f"{nick}: {text}", self.my_color); self.entry.delete(0,"end"); return
            else:
                if not self.active_sock or not self.session_password:
                    messagebox.showinfo("Note", "No session key (handshake not complete)."); return
                # Rotation falls nötig
                cnt = getattr(self, "_client_count", 0)
                if cnt >= self.ROTATE_EVERY:
                    self._client_initiate_rekey(); cnt = 0
                # Send
                mid = base64.b64encode(os.urandom(12)).decode("ascii")
                if not self._rate.allow():
                    messagebox.showwarning("Rate limit","Too many messages – wait a moment."); return
                cnt = getattr(self, "_client_count", 0)
                pad = _rand_pad_b64()
                payload = json.dumps({"t": text, "pad": pad})
                aad = self._aad_for("msg", counter=cnt+1, peer_client_id=_get_client_id())
                _jitter_sleep()
                blob_b64 = encrypt_text(payload, self.session_password, aad_text=aad, kdf_profile=self.kdf_profile, add_prefix=False)
                send_json(self.active_sock, {"type":"msg","blob": blob_b64, "nick": nick, "mid": mid, "ctr": cnt+1})
                self._client_count = cnt + 1
                self.log_colored(f"{nick}: {text}", self.my_color); self.entry.delete(0,"end")
        except Exception as e:
            messagebox.showerror("Send fehlgeschlagen", str(e))

    def send_file(self):
        path = filedialog.askopenfilename()
        if not path: return
        p = Path(path)
        try:
            with open(p, "rb") as f: data=f.read()
            # Verschlüsseln mit Session-Key
            if self.role == "server":
                if not self.clients: messagebox.showinfo("Note","Kein Client verbunden."); return
                dead=[]
                for c in list(self.clients):
                    try:
                        sess = self.sessions.get(c)
                        if not sess: continue
                        if not self._rate.allow():
                            continue
                        
                        sess["count"] = int(sess.get("count",0))
                        cnt = sess["count"] + 1
                        peer_cid = self.clients_id_map.get(c, "")
                        aad_s = self._aad_for("file", name=p.name, size=len(data), counter=cnt, peer_client_id=peer_cid)
                        _jitter_sleep()
                        enc = encrypt_data(data, sess["sess_pw"], aad=aad_s.encode("utf-8"), kdf_profile=self.kdf_profile)
                        sess["count"] = cnt
                        mid = base64.b64encode(os.urandom(12)).decode("ascii")
                        send_json(c, {"type":"file","name": p.name, "size": len(enc), "mid": mid, "ctr": cnt})
                        off=0
                        while off < len(enc):
                            chunk=enc[off:off+65536]; c.sendall(chunk); off += len(chunk)
                    except Exception: dead.append(c)
                for d in dead:
                    try: self.clients.discard(d)
                    except Exception: pass
            else:
                if not self.active_sock or not self.session_password: messagebox.showinfo("Note","No session key (handshake not complete)."); return
                if not self._rate.allow():
                    return
                cnt = getattr(self, "_client_count", 0) + 1
                aad_s = self._aad_for("file", name=p.name, size=len(data), counter=cnt, peer_client_id=_get_client_id())
                _jitter_sleep()
                enc = encrypt_data(data, self.session_password, aad=aad_s.encode("utf-8"), kdf_profile=self.kdf_profile)
                mid = base64.b64encode(os.urandom(12)).decode("ascii")
                self._client_count = cnt
                send_json(self.active_sock, {"type":"file","name": p.name, "size": len(enc), "mid": mid, "ctr": cnt})
                off=0
                while off < len(enc):
                    chunk=enc[off:off+65536]; self.active_sock.sendall(chunk); off += len(chunk)
            self.log(f"📦 File sent: {p.name} ({p.stat().st_size} Bytes)")
        except Exception as e:
            messagebox.showerror("Send fehlgeschlagen", str(e))


    # --- NullCrypto manuell: Eingabe-Text ---
    def _nc_encrypt_entry(self):
        try:
            pw = (self.nc_pw.get().strip() if hasattr(self, 'nc_pw') else '')
            if not pw:
                self.set_status('NullCrypto: Password missing'); return
            text = self.entry.get().strip()
            if not text:
                self.set_status('NullCrypto: Input empty'); return
            aad = self.room
            out = encrypt_text(text, pw, aad_text=aad, kdf_profile=self.kdf_profile, add_prefix=False)
            self.entry.delete(0, 'end'); self.entry.insert(0, out)
            self.set_status('NullCrypto: Text encrypted (manuell)')
        except Exception as e:
            self.set_status(f'NullCrypto Encrypt error: {e}')

    def _nc_decrypt_entry(self):
        try:
            pw = (self.nc_pw.get().strip() if hasattr(self, 'nc_pw') else '')
            if not pw:
                self.set_status('NullCrypto: Password missing'); return
            blob = self.entry.get().strip()
            if not blob:
                self.set_status('NullCrypto: Input empty'); return
            aad = self.room
            out = decrypt_text(blob, pw, aad_text=aad, kdf_profile=self.kdf_profile)
            self.entry.delete(0, 'end'); self.entry.insert(0, out)
            self.set_status('NullCrypto: Text decrypted (manuell)')
        except Exception as e:
            self.set_status(f'NullCrypto Decrypt error: {e}')

    # --- NullCrypto manuell: Dateien ---
    def _nc_encrypt_file_dialog(self):
        try:
            pw = (self.nc_pw.get().strip() if hasattr(self, 'nc_pw') else '')
            if not pw:
                self.set_status('NullCrypto: Password missing'); return
            path = filedialog.askopenfilename(title='Choose file to NC-encrypt')
            if not path: return
            out = encrypt_file(path, None, pw, aad_text=self.room, kdf_profile=self.kdf_profile)
            self.log(f'[NC] Encrypted → {out}')
            self.set_status('NullCrypto: File encrypted')
        except Exception as e:
            self.set_status(f'NullCrypto File-Encrypt error: {e}')

    def _nc_decrypt_file_dialog(self):
        try:
            pw = (self.nc_pw.get().strip() if hasattr(self, 'nc_pw') else '')
            if not pw:
                self.set_status('NullCrypto: Password missing'); return
            path = filedialog.askopenfilename(title='Choose NC-encrypted file (.scube)')
            if not path: return
            out = decrypt_file(path, None, pw, aad_text=self.room, kdf_profile=self.kdf_profile)
            self.log(f'[NC] Decrypted → {out}')
            self.set_status('NullCrypto: File decrypted')
        except Exception as e:
            self.set_status(f'NullCrypto File-Decrypt error: {e}')
def start_local_server(port: int, on_client):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(5)
    def accept_loop():
        while True:
            try: c, addr = s.accept()
            except OSError: break
            threading.Thread(target=on_client, args=(c,), daemon=True).start()
    threading.Thread(target=accept_loop, daemon=True).start(); return s

def main():
    app = NullMessenger(); app.mainloop()

if __name__ == "__main__":
    main()
