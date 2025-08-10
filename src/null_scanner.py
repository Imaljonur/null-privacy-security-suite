
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import threading
import socket
import ssl
from contextlib import closing
from datetime import datetime, timezone
import argparse
import re
import time
import random
import hashlib
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# --- Optional dependencies (graceful degrade) ---
try:
    import customtkinter as ctk
    from tkinter import ttk, filedialog, messagebox
except Exception:
    ctk = None  # Running headless or without GUI environment
try:
    import dns.resolver
    import dns.reversename
except Exception:
    dns = None
try:
    import httpx
except Exception:
    httpx = None
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except Exception:
    x509 = None
try:
    import mmh3
except Exception:
    mmh3 = None
try:
    import socks  # PySocks
except Exception:
    socks = None
try:
    import numpy as np
    import pandas as pd
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import roc_auc_score, classification_report
    import joblib
except Exception:
    np = pd = LogisticRegression = train_test_split = roc_auc_score = classification_report = joblib = None
try:
    import lightgbm as lgb
except Exception:
    lgb = None

# ------------------------------
#   Heuristic C2 analyzer core
# ------------------------------

DEFAULT_PORTS = [80, 443, 8080, 8443, 22, 53, 4444, 6667, 9001, 1337]

# Defaults tuned by "profile" later
HTTP_TIMEOUT = 10.0
TCP_TIMEOUT  = 7.0
TLS_TIMEOUT  = 10.0

# Legacy placeholder (unused for matching now – use FAVICON_DB instead)
KNOWN_FAVICON_HASHES = {
    # "116323821": "Cobalt Strike (example)"
}

# External favicon DB (algo:hash -> label), loadable via --favicon-db
FAVICON_DB = {}

def load_favicon_db(path: str):
    """Load a JSON DB mapping '<algo>:<hash>' -> 'label'."""
    global FAVICON_DB
    try:
        p = Path(path)
        if p.exists():
            FAVICON_DB = json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        FAVICON_DB = {}

SUSPICIOUS_SERVER_TOKENS = [
    "Apache/2.4.1 (Unix)", "nginx/1.10.3", "Microsoft-IIS/6.0"
]

COMMON_C2_PATHS = ["/","/favicon.ico","/robots.txt"]

BANNER_PORTS = {22, 80, 443, 8080, 8443, 6667}


def score_add(state, points, reason):
    state["score"] += points
    state["reasons"].append({"points": float(points), "reason": reason})


def sanitize_target(raw: str) -> str:
    s = (raw or "").strip()
    s = re.sub(r'^\s*(?:[a-zA-Z][a-zA-Z0-9+\-.]*://)', '', s)
    s = re.sub(r'^[^/@]+@', '', s)
    s = re.split(r'[/?#]', s, 1)[0]
    s = s.strip("[]").strip()
    s = re.sub(r':\d+$', '', s)
    s = s.strip().lower()
    try:
        socket.inet_pton(socket.AF_INET, s); return s
    except OSError: pass
    try:
        socket.inet_pton(socket.AF_INET6, s); return s
    except OSError: pass
    if s.endswith(".onion"):
        return s
    try:
        return s.encode("idna").decode("ascii")
    except Exception:
        return s


def resolve_dns(name_or_ip, use_tor=False):
    result = {
        "input": name_or_ip,
        "is_ip": False,
        "fqdn": None,
        "a_records": [],
        "aaaa_records": [],
        "ptr": None,
        "ttls": [],
        "errors": [],
        "note": ""
    }
    # IP?
    try:
        socket.inet_pton(socket.AF_INET, name_or_ip)
        result["is_ip"] = True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, name_or_ip)
            result["is_ip"] = True
        except OSError:
            result["is_ip"] = False

    if use_tor and not result["is_ip"]:
        result["fqdn"] = str(name_or_ip).strip(".")
        result["note"] = "TOR enabled: skipping A/AAAA resolution (rdns via SOCKS5h)."
        return result

    if 'dns' in globals() and dns is not None:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.5
        try:
            if not result["is_ip"]:
                result["fqdn"] = str(name_or_ip).strip(".")
                for rtype in ("A","AAAA"):
                    try:
                        ans = resolver.resolve(result["fqdn"], rtype)
                        addrs = sorted({str(r) for r in ans})
                        if rtype == "A":
                            result["a_records"] = addrs
                        else:
                            result["aaaa_records"] = addrs
                        result["ttls"].append(ans.rrset.ttl if hasattr(ans, "rrset") else None)
                    except Exception:
                        pass
            else:
                try:
                    rev = dns.reversename.from_address(name_or_ip)
                    ans = resolver.resolve(rev, "PTR")
                    result["ptr"] = str(ans[0]).rstrip(".")
                except Exception:
                    pass
        except Exception as e:
            result["errors"].append(f"DNS error: {e}")
        return result

    # Fallback without dnspython
    result["errors"].append("dnspython not installed – DNS checks limited.")
    try:
        if not result["is_ip"] and not use_tor:
            a = socket.getaddrinfo(name_or_ip, None)
            ips = sorted({x[4][0] for x in a})
            result["a_records"]   = [ip for ip in ips if ":" not in ip]
            result["aaaa_records"] = [ip for ip in ips if ":" in ip]
        elif result["is_ip"]:
            try:
                ptr_name, _, _ = socket.gethostbyaddr(name_or_ip)
                result["ptr"] = ptr_name.rstrip(".")
            except Exception:
                pass
    except Exception as e:
        result["errors"].append(f"getaddrinfo error: {e}")
    return result

def _addr_family(host: str):
    try:
        socket.inet_pton(socket.AF_INET6, host); return socket.AF_INET6
    except OSError:
        return socket.AF_INET

def _make_socket(use_tor=False, tor_host="127.0.0.1", tor_port=9050, family=socket.AF_INET):
    if use_tor and socks is not None:
        s = socks.socksocket(family, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, tor_host, tor_port, rdns=True)
        s.settimeout(TCP_TIMEOUT)
        return s
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(TCP_TIMEOUT)
    return s


def tcp_connect(host, port, use_tor=False, tor_host="127.0.0.1", tor_port=9050):
    fam = _addr_family(host)
    with closing(_make_socket(use_tor, tor_host, tor_port, family=fam)) as s:
        try:
            if fam == socket.AF_INET6:
                s.connect((host, port, 0, 0))
            else:
                s.connect((host, port))
            return True
        except Exception:
            return False


def tcp_banner(host, port, use_tor=False, tor_host="127.0.0.1", tor_port=9050, read_bytes=160, wait=0.6):
    fam = _addr_family(host)
    with closing(_make_socket(use_tor, tor_host, tor_port, family=fam)) as s:
        try:
            if fam == socket.AF_INET6:
                s.connect((host, port, 0, 0))
            else:
                s.connect((host, port))
            s.settimeout(wait)
            try:
                data = s.recv(read_bytes)
                return data.decode(errors="ignore")
            except Exception:
                return ""
        except Exception:
            return ""


def _http_client(use_tor=False, tor_host="127.0.0.1", tor_port=9050):
    if httpx is None:
        return None, "httpx not installed"
    proxies = None
    if use_tor:
        proxies = {
            "http":  f"socks5h://{tor_host}:{tor_port}",
            "https": f"socks5h://{tor_host}:{tor_port}",
        }
    try:
        if proxies is None:
            client = httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False, headers={"User-Agent":"Mozilla/5.0"})
        else:
            client = httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False, proxies=proxies, headers={"User-Agent":"Mozilla/5.0"})
        return client, None
    except TypeError as e:
        return None, f"httpx 'proxies' not supported here: {e}"
    except Exception as e:
        return None, str(e)

def _fmt_host_for_url(h: str) -> str:
    try:
        socket.inet_pton(socket.AF_INET6, h)
        return f"[{h}]"
    except OSError:
        return h

def http_probe(scheme, host, port, path="/", use_tor=False, tor_host="127.0.0.1", tor_port=9050):
    url = f"{scheme}://{_fmt_host_for_url(host)}:{port}{path}"
    if httpx is None:
        # Fallback with urllib (no TOR support here)
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent":"Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                headers = dict(r.headers)
                status = getattr(r, "status", 200)
                body_len = int(headers.get("Content-Length","0")) if "Content-Length" in headers else 0
                info = {
                    "url": url,
                    "status_code": status,
                    "headers": headers,
                    "body_len": body_len,
                    "server": headers.get("Server"),
                    "location": headers.get("Location"),
                    "content_type": headers.get("Content-Type")
                }
                if status in (200, 301, 302, 307, 308) and body_len == 0:
                    try:
                        req2 = urllib.request.Request(url, method="GET", headers={"User-Agent":"Mozilla/5.0"})
                        with urllib.request.urlopen(req2, timeout=HTTP_TIMEOUT) as r2:
                            data = r2.read()
                            info["status_code"] = getattr(r2, "status", info["status_code"])
                            info["headers"] = dict(r2.headers)
                            info["server"] = info["headers"].get("Server")
                            info["location"] = info["headers"].get("Location")
                            info["content_type"] = info["headers"].get("Content-Type")
                            info["body_len"] = len(data or b"")
                    except Exception:
                        pass
                return info
        except urllib.error.HTTPError as e:
            return {"url": url, "status_code": e.code, "headers": dict(e.headers or {}), "body_len": 0,
                    "server": (e.headers or {}).get("Server"), "location": (e.headers or {}).get("Location"),
                    "content_type": (e.headers or {}).get("Content-Type")}
        except Exception as e:
            return {"url": url, "error": str(e)}
    client, err = _http_client(use_tor, tor_host, tor_port)
    if client is None:
        return {"url": url, "error": err or "http client init failed"}
    try:
        r = client.head(url)
        status = r.status_code
        headers = dict(r.headers)
        body_len = int(headers.get("Content-Length","0")) if "Content-Length" in headers else 0
        info = {
            "url": url,
            "status_code": status,
            "headers": headers,
            "body_len": body_len,
            "server": headers.get("Server"),
            "location": headers.get("Location"),
            "content_type": headers.get("Content-Type")
        }
        if status in (200, 301, 302, 307, 308) and body_len == 0:
            r2 = client.get(url)
            info["status_code"] = r2.status_code
            info["headers"] = dict(r2.headers)
            info["server"] = r2.headers.get("Server")
            info["location"] = r2.headers.get("Location")
            info["content_type"] = r2.headers.get("Content-Type")
            info["body_len"] = len(r2.content or b"")
        return info
    except Exception as e:
        return {"url": url, "error": str(e)}
    finally:
        try:
            client.close()
        except Exception:
            pass


def fetch_favicon_hash(scheme, host, port, use_tor=False, tor_host="127.0.0.1", tor_port=9050):
    url = f"{scheme}://{_fmt_host_for_url(host)}:{port}/favicon.ico"
    # fetch
    content = None
    if httpx is None:
        try:
            with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as r:
                if getattr(r, "status", 200) == 200:
                    content = r.read()
        except Exception as e:
            return {"url": url, "error": f"fetch fail: {e}"}
    else:
        client, err = _http_client(use_tor, tor_host, tor_port)
        if client is None:
            return {"url": url, "error": err or "http client init failed"}
        try:
            r = client.get(url)
            if r.status_code == 200 and r.content:
                content = r.content
            else:
                return {"url": url, "status": r.status_code}
        except Exception as e:
            return {"url": url, "error": str(e)}
        finally:
            try:
                client.close()
            except Exception:
                pass

    if not content:
        return {"url": url, "status": 404}

    # hash
    import base64
    b64 = base64.b64encode(content)
    out = {"url": url, "status": 200}
    if mmh3 is not None:
        out["hash"] = str(mmh3.hash(b64))
        out["algo"] = "mmh3"
    else:
        md5 = hashlib.md5(b64).hexdigest()
        out["hash"] = md5
        out["algo"] = "md5b64"
    return out


def tls_cert_probe(host, port=443, use_tor=False, tor_host="127.0.0.1", tor_port=9050):
    out = {"host": host, "port": port}
    try:
        fam = _addr_family(host)
        base_sock = _make_socket(use_tor, tor_host, tor_port, family=fam)
        with closing(base_sock) as sock:
            sock.settimeout(TLS_TIMEOUT)
            if fam == socket.AF_INET6:
                sock.connect((host, port, 0, 0))
            else:
                sock.connect((host, port))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # stdlib cert + DER form
                cert = ssock.getpeercert(binary_form=False)
                cert_der = ssock.getpeercert(binary_form=True)
                out["cipher"]      = ssock.cipher()
                out["tls_version"] = ssock.version()
                ocsp = getattr(ssock, "ocsp_response", None)
                out["ocsp_stapled"] = bool(ocsp) and len(ocsp or b"") > 0
        if x509 is not None:
            certx = x509.load_der_x509_certificate(cert_der, default_backend())
            subject = certx.subject.rfc4514_string()
            issuer  = certx.issuer.rfc4514_string()
            not_before = certx.not_valid_before.replace(tzinfo=timezone.utc)
            not_after  = certx.not_valid_after.replace(tzinfo=timezone.utc)
            out.update({
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before.isoformat(),
                "not_after":  not_after.isoformat(),
                "valid_days": (not_after - not_before).days,
                "self_signed_like": subject == issuer
            })
        else:
            # parse stdlib dict
            try:
                nb = cert.get("notBefore")
                na = cert.get("notAfter")
                fmt = "%b %d %H:%M:%S %Y %Z"
                nb_dt = datetime.strptime(nb, fmt) if nb else None
                na_dt = datetime.strptime(na, fmt) if na else None
                subj = ", ".join(f"{k}={v}" for (k, v) in sum((t[0] for t in cert.get("subject", [])), [])) if cert.get("subject") else None
                iss  = ", ".join(f"{k}={v}" for (k, v) in sum((t[0] for t in cert.get("issuer", [])), [])) if cert.get("issuer") else None
                if nb_dt: out["not_before"] = nb_dt.replace(tzinfo=timezone.utc).isoformat()
                if na_dt: out["not_after"]  = na_dt.replace(tzinfo=timezone.utc).isoformat()
                if nb_dt and na_dt:
                    out["valid_days"] = (na_dt - nb_dt).days
                out["subject"] = subj
                out["issuer"]  = iss
                out["self_signed_like"] = (subj == iss) if subj and iss else False
            except Exception:
                out["note"] = "cryptography not installed – certificate parsed in a basic way."
        return out
    except Exception as e:
        out["error"] = str(e)
        return out


def looks_fast_flux(a_records, ttls):
    try:
        ttl_min = min([t for t in ttls if t is not None]) if ttls else None
    except ValueError:
        ttl_min = None
    return (len(a_records) >= 4) or (ttl_min is not None and ttl_min <= 120)


def entropy_ratio(s):
    if not s:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(s)
    probs = [c/len(s) for c in counts.values()]
    ent = -sum(p*math.log2(p) for p in probs)
    return ent / (math.log2(len(counts)) if len(counts) > 1 else 1.0)


def apply_profile(profile, use_tor=False):
    global HTTP_TIMEOUT, TCP_TIMEOUT, TLS_TIMEOUT
    if profile == "Stealth":
        HTTP_TIMEOUT, TCP_TIMEOUT, TLS_TIMEOUT = 12.0, 9.0, 12.0
        jitter = (0.25, 0.8)
        max_workers = 4 if use_tor else 6
        rps = 1.0
    elif profile == "Aggressiv" or profile == "Aggressive":
        HTTP_TIMEOUT, TCP_TIMEOUT, TLS_TIMEOUT = 8.0, 5.0, 8.0
        jitter = (0.0, 0.2)
        max_workers = 8 if use_tor else 16
        rps = 6.0
    else:  # Balanced
        HTTP_TIMEOUT, TCP_TIMEOUT, TLS_TIMEOUT = 10.0, 7.0, 10.0
        jitter = (0.1, 0.5)
        max_workers = 6 if use_tor else 10
        rps = 3.0
    return jitter, max_workers, rps

class RateLimiter:
    def __init__(self, rps: float):
        self.min_interval = 1.0 / max(rps, 0.1)
        self.lock = threading.Lock()
        self.next_time = 0.0
    def wait(self):
        with self.lock:
            now = time.monotonic()
            if now < self.next_time:
                time.sleep(self.next_time - now)
                now = time.monotonic()
            self.next_time = now + self.min_interval


def analyze(raw_target, ports, use_tor=False, tor_host="127.0.0.1", tor_port=9050, profile="Balanced", do_banner=True):
    target = sanitize_target(raw_target)
    jitter, max_workers, rps = apply_profile(profile, use_tor=use_tor)
    limiter = RateLimiter(rps)

    report = {
        "tool": "null_inspector",
        "target": target,
        "input_raw": raw_target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "score": 0.0,
        "reasons": [],
        "dns": {},
        "ports": {},
        "banners": {},
        "http": [],
        "tls": {},
        "favicon": {},
        "verdict": "",
        "summary": "",
        "tor": {"enabled": use_tor, "host": tor_host, "port": tor_port},
        "profile": profile
    }

    # DNS
    dns_info = resolve_dns(target, use_tor=use_tor)
    report["dns"] = dns_info
    if not use_tor and dns_info.get("a_records"):
        if looks_fast_flux(dns_info["a_records"], dns_info.get("ttls", [])):
            score_add(report, 2.0, "DNS hints at possible fast-flux (many A records / small TTL).")
    if dns_info.get("ptr"):
        if entropy_ratio(dns_info["ptr"]) > 0.8:
            score_add(report, 1.0, "PTR name looks high-entropy / auto-generated.")

    # Host for scan
    if dns_info.get("a_records") and not use_tor:
        host_for_scan = dns_info["a_records"][0]
    else:
        host_for_scan = target

    # Ports + Banners (concurrent)
    def _scan_port(p):
        time.sleep(random.uniform(*jitter))
        limiter.wait()
        is_open = tcp_connect(host_for_scan, p, use_tor=use_tor, tor_host=tor_host, tor_port=tor_port)
        banner = ""
        if is_open and do_banner and p in BANNER_PORTS:
            limiter.wait()
            banner = tcp_banner(host_for_scan, p, use_tor=use_tor, tor_host=tor_host, tor_port=tor_port)
        return p, is_open, banner

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(_scan_port, p) for p in ports]
        for f in as_completed(futs):
            p, is_open, banner = f.result()
            report["ports"][p] = {"open": bool(is_open)}
            if banner:
                report["banners"][p] = banner[:200]
            if is_open and p in (4444, 6667, 9001, 1337):
                score_add(report, 1.0, f"Unusual open port {p} (common with C2/IRC/Tor).")
            time.sleep(random.uniform(*jitter))

    # HTTP(S) over selected ports & paths (concurrent)
    http_targets = []
    for p in ports:
        scheme = "https" if p in (443, 8443) else "http"
        if p in (80, 443, 8080, 8443):
            for path in COMMON_C2_PATHS:
                http_targets.append((scheme, host_for_scan, p, path))

    def _scan_http(args):
        time.sleep(random.uniform(*jitter))
        limiter.wait()
        scheme, host, p, path = args
        return http_probe(scheme, host, p, path, use_tor=use_tor, tor_host=tor_host, tor_port=tor_port)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(_scan_http, t) for t in http_targets]
        for f in as_completed(futs):
            info = f.result()
            report["http"].append(info)
            if isinstance(info, dict) and "error" not in info:
                server = (info.get("server") or "").strip()
                if server in SUSPICIOUS_SERVER_TOKENS:
                    score_add(report, 1.0, f"Unusual/placeholder Server header: {server}")
                sc = info.get("status_code")
                bl = info.get("body_len", 0)
                if sc in (301,302,307,308) and bl == 0:
                    score_add(report, 0.5, f"Empty redirect at {info.get('url')} – possible decoy.")
                if sc in (403,404) and bl <= 100:
                    score_add(report, 0.5, f"Very sparse error page ({sc}, {bl} B).")
            time.sleep(random.uniform(*jitter))

    # Favicon on common ports (sequential)
    for p in (80,8080,443,8443):
        scheme = "https" if p in (443,8443) else "http"
        limiter.wait()
        fav = fetch_favicon_hash(scheme, host_for_scan, p, use_tor=use_tor, tor_host=tor_host, tor_port=tor_port)
        report["favicon"][f"{scheme}:{p}"] = fav
        if isinstance(fav, dict):
            h = fav.get("hash")
            algo = fav.get("algo","mmh3")
            key = f"{algo}:{h}" if h else None
            if key and key in FAVICON_DB:
                score_add(report, 3.0, f"Favicon match ({key}) → {FAVICON_DB[key]}")
        time.sleep(random.uniform(*jitter))

    # TLS
    if any(report["ports"].get(p,{}).get("open") for p in (443,8443)):
        port_tls = 443 if report["ports"].get(443,{}).get("open") else 8443
        limiter.wait()
        tls = tls_cert_probe(host_for_scan, port_tls, use_tor=use_tor, tor_host=tor_host, tor_port=tor_port)
        report["tls"] = tls
        if "error" not in tls and tls:
            if tls.get("self_signed_like"):
                score_add(report, 1.5, "TLS certificate appears self-signed.")
            vd = tls.get("valid_days")
            if isinstance(vd, int) and vd <= 90:
                score_add(report, 1.0, f"Very short certificate validity ({vd} days).")
            # expired?
            try:
                na = tls.get("not_after")
                if na:
                    na_dt = datetime.fromisoformat(na.replace("Z","+00:00"))
                    if na_dt < datetime.now(timezone.utc):
                        score_add(report, 0.8, "TLS certificate is expired.")
            except Exception:
                pass
            if tls.get("ocsp_stapled") is False:
                score_add(report, 0.2, "OCSP stapling not present.")
            subj = tls.get("subject") or ""
            if subj and entropy_ratio(subj) > 0.75:
                score_add(report, 0.5, "Certificate subject looks synthetic/high-entropy.")

    s = report["score"]
    if s >= 5:
        verdict = "HIGH RISK (suspicious)"
    elif s >= 2.5:
        verdict = "MEDIUM RISK (notable)"
    elif s > 0:
        verdict = "LOW RISK (minor signals)"
    else:
        verdict = "UNSUSPICIOUS by heuristics"
    report["verdict"] = verdict
    report["summary"] = f"Score: {s:.1f} → {verdict}. Signals: {len(report['reasons'])}."
    return report


# ---------------------------------------------
#  Heuristic AI (fallback if no ML model)
# ---------------------------------------------

def ai_probability_heuristic(report):
    # favicon hit against FAVICON_DB
    fav_hit = 0.0
    for v in report.get("favicon",{}).values():
        if isinstance(v, dict) and v.get("hash"):
            key = f"{v.get('algo','mmh3')}:{v.get('hash')}"
            if key in FAVICON_DB:
                fav_hit = 1.0
                break
    f = {
        "score": float(report.get("score", 0.0)),
        "open_weird_ports": sum(1 for p in (4444,6667,9001,1337) if report.get("ports",{}).get(p,{}).get("open")),
        "fast_flux": 1.0 if looks_fast_flux(report.get("dns",{}).get("a_records",[]),
                                            report.get("dns",{}).get("ttls",[])) else 0.0,
        "self_signed": 1.0 if report.get("tls",{}).get("self_signed_like") else 0.0,
        "short_cert": 1.0 if isinstance(report.get("tls",{}).get("valid_days"), int) and report["tls"]["valid_days"] <= 90 else 0.0,
        "favicon_hit": fav_hit,
    }
    w = {"bias": -2.2, "score": 0.45, "open_weird_ports": 0.8, "fast_flux": 1.1, "self_signed": 0.6, "short_cert": 0.5, "favicon_hit": 1.6}
    import math
    z = (w["bias"] + w["score"]*f["score"] + w["open_weird_ports"]*f["open_weird_ports"]
         + w["fast_flux"]*f["fast_flux"] + w["self_signed"]*f["self_signed"]
         + w["short_cert"]*f["short_cert"] + w["favicon_hit"]*f["favicon_hit"])
    prob = 1.0 / (1.0 + math.exp(-z))
    explanation = [k.replace("_"," ") for k,v in f.items() if v]
    return float(prob), f, explanation


# ---------------------------------------------
#  ML utilities
# ---------------------------------------------

FEATURE_ORDER = [
    "score",
    "num_open_ports",
    "num_weird_ports",
    "fast_flux",
    "tls_self_signed",
    "tls_valid_days",
    "http_num_200",
    "http_num_3xx",
    "http_num_4xx",
    "http_avg_body",
    "favicon_hit",
    "ptr_entropy",
    "cert_subject_entropy",
]

def _entropy(s):
    if not s:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(s)
    probs = [c/len(s) for s_, c in counts.items()]
    ent = -sum(p*math.log2(p) for p in probs)
    return float(ent)


def extract_features(report: dict) -> dict:
    ports = report.get("ports", {})
    http = [h for h in report.get("http", []) if isinstance(h, dict) and "error" not in h]
    tls  = report.get("tls", {})
    dnsr = report.get("dns", {})
    favs = report.get("favicon", {})

    num_open_ports = sum(1 for v in ports.values() if v.get("open"))
    num_weird_ports = sum(1 for p,v in ports.items() if v.get("open") and p in (4444,6667,9001,1337))

    http_codes = [int(h.get("status_code", 0)) for h in http if isinstance(h.get("status_code", None), (int,))]
    http_num_200 = sum(1 for c in http_codes if 200 <= c < 300)
    http_num_3xx = sum(1 for c in http_codes if 300 <= c < 400)
    http_num_4xx = sum(1 for c in http_codes if 400 <= c < 500)
    http_avg_body = float(sum(h.get("body_len", 0) for h in http) / max(1, len(http)))

    fast = looks_fast_flux(dnsr.get("a_records", []), dnsr.get("ttls", []))
    fav_hit = 0.0
    for v in favs.values():
        if isinstance(v, dict):
            h = v.get("hash")
            if h:
                key = f"{v.get('algo','mmh3')}:{h}"
                if key in FAVICON_DB:
                    fav_hit = 1.0
                    break

    subj = tls.get("subject") or ""
    ptr  = dnsr.get("ptr") or ""
    features = {
        "score": float(report.get("score", 0.0)),
        "num_open_ports": float(num_open_ports),
        "num_weird_ports": float(num_weird_ports),
        "fast_flux": 1.0 if fast else 0.0,
        "tls_self_signed": 1.0 if tls.get("self_signed_like") else 0.0,
        "tls_valid_days": float(tls.get("valid_days", 0) or 0),
        "http_num_200": float(http_num_200),
        "http_num_3xx": float(http_num_3xx),
        "http_num_4xx": float(http_num_4xx),
        "http_avg_body": float(http_avg_body),
        "favicon_hit": float(fav_hit),
        "ptr_entropy": _entropy(ptr),
        "cert_subject_entropy": _entropy(subj),
    }
    return features


def features_to_vector(feat: dict):
    return [feat.get(k, 0.0) for k in FEATURE_ORDER]


def load_model(model_path: str):
    if joblib is None:
        return None, "joblib/sklearn not installed"
    p = Path(model_path)
    if not p.exists():
        return None, "no model found"
    try:
        model = joblib.load(p)
        return model, None
    except Exception as e:
        return None, f"model could not be loaded: {e}"


def train_model(data_dir: str, out_path: str, algo: str = "logreg"):
    if pd is None or np is None or joblib is None:
        raise RuntimeError("Training requires numpy, pandas, scikit-learn, joblib.")

    data_dir = Path(data_dir)
    labels_csv = data_dir / "labels.csv"
    reports_dir = data_dir / "reports"
    if not labels_csv.exists() or not reports_dir.exists():
        raise RuntimeError("Expect folder with labels.csv and subfolder reports/ containing JSON reports.")

    labels = pd.read_csv(labels_csv)
    if "target" not in labels.columns or "label" not in labels.columns:
        raise RuntimeError("labels.csv must contain columns 'target' and 'label' (0/1).")

    X_list, y_list = [], []
    for _, row in labels.iterrows():
        tgt = str(row["target"]).strip()
        y = int(row["label"])
        # try matching file null_inspector_{target}.json or anything containing target
        candidates = list(reports_dir.glob(f"*{tgt}*.json"))
        if not candidates:
            continue
        try:
            with open(candidates[0], "r", encoding="utf-8") as f:
                rep = json.load(f)
            feat = extract_features(rep)
            X_list.append(features_to_vector(feat))
            y_list.append(y)
        except Exception:
            pass

    if not X_list:
        raise RuntimeError("No training data found (do labels match reports?).")

    X = np.array(X_list, dtype=float)
    y = np.array(y_list, dtype=int)

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    if algo == "lgbm" and lgb is not None:
        dtrain = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_ORDER, free_raw_data=False)
        dval = lgb.Dataset(X_val, label=y_val, reference=dtrain, feature_name=FEATURE_ORDER, free_raw_data=False)
        params = {"objective": "binary", "metric": "auc", "learning_rate": 0.05, "num_leaves": 31}
        model = lgb.train(params, dtrain, valid_sets=[dtrain, dval], num_boost_round=400, callbacks=[lgb.early_stopping(50)])
        val_pred = model.predict(X_val)
    else:
        model = LogisticRegression(max_iter=200, n_jobs=1, solver="lbfgs")
        model.fit(X_train, y_train)
        val_pred = model.predict_proba(X_val)[:,1]

    auc = roc_auc_score(y_val, val_pred)
    print(f"AUC(valid) = {auc:.3f}")
    if algo != "lgbm":
        print(classification_report(y_val, (val_pred>=0.5).astype(int)))
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "features": FEATURE_ORDER, "algo": algo}, out_path)
    print(f"Model saved: {out_path}")


def ml_predict(model_bundle, report: dict):
    model = model_bundle.get("model")
    feats = features_to_vector(extract_features(report))
    import numpy as np
    X = np.array([feats], dtype=float)
    if hasattr(model, "predict_proba"):
        p = float(model.predict_proba(X)[0,1])
        # Explain with linear coef if available
        if hasattr(model, "coef_"):
            weights = model.coef_[0]
            pairs = sorted([(FEATURE_ORDER[i], float(weights[i]*X[0,i])) for i in range(len(FEATURE_ORDER))],
                           key=lambda t: abs(t[1]), reverse=True)
            explanation = [f"{k}" for k,_ in pairs[:5]]
        else:
            explanation = []
    else:
        # LightGBM
        p = float(model.predict(X)[0])
        explanation = []  # Keep it simple; could add SHAP later
    return p, explanation


# ------------------------------
#  GUI (CustomTkinter) Layer
# ------------------------------

ACCENT  = "#00FF88"
BG_DARK = "#0B0F10"
BG_CARD = "#12171A"
FG_TEXT = "#D7E0E6"
FG_MUTED= "#8FA3AD"
BORDER  = "#1D252B"

def _theme_setup():
    if ctk:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

def _style_ttk_dark():
    try:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=BG_CARD, borderwidth=0)
        style.configure("TNotebook.Tab", background="#0E1316", foreground=FG_TEXT, padding=[10,6])
        style.map("TNotebook.Tab", background=[("selected", BG_DARK)], foreground=[("selected", ACCENT)])
        style.configure("Treeview",
                        background="#0E1316",
                        fieldbackground="#0E1316",
                        foreground=FG_TEXT,
                        bordercolor=BORDER,
                        borderwidth=0,
                        rowheight=26)
        style.map("Treeview", background=[("selected", "#1F2A30")], foreground=[("selected", FG_TEXT)])
        style.configure("Treeview.Heading", background=BG_CARD, foreground=FG_MUTED)
    except Exception:
        pass

def _card(parent, **kwargs):
    opts = dict(fg_color=BG_CARD, corner_radius=14, border_color=BORDER, border_width=1)
    opts.update(kwargs)
    return ctk.CTkFrame(parent, **opts)

def _label(parent, text, muted=False):
    return ctk.CTkLabel(parent, text=text, text_color=(FG_MUTED if muted else FG_TEXT))

def _btn_primary(parent, text, command=None):
    return ctk.CTkButton(parent, text=text, fg_color=ACCENT, text_color="black", command=command)

def _btn_subtle(parent, text, command=None):
    return ctk.CTkButton(parent, text=text, fg_color="#1F2933", hover_color="#25313B", command=command)

def _textbox(parent, height=120):
    tb = ctk.CTkTextbox(parent, height=height, fg_color="#0E1316", text_color=FG_TEXT, border_color=BORDER, border_width=1, corner_radius=10, wrap="word")
    tb.configure(state="normal")
    return tb


class NullInspectorMLApp(ctk.CTk):
    def __init__(self, model_path="models/null_inspector_model.joblib"):
        super().__init__()
        _theme_setup()
        self.title("null_inspector + ML")
        self.geometry("1320x920")
        self.configure(fg_color=BG_DARK)

        self.model_bundle = None
        self.model_path = model_path
        self._try_load_model()

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        # Sidebar
        sb = _card(self); sb.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        sb.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(sb, text="null_inspector + ML", text_color=ACCENT, font=ctk.CTkFont(size=20, weight="bold"))
        title.grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        model_status = "loaded" if self.model_bundle else "not loaded"
        _label(sb, f"ML model: {model_status}", muted=True).grid(row=1, column=0, padx=16, pady=(0,8), sticky="w")

        self.entry_target = ctk.CTkEntry(sb, placeholder_text="Domain or IP… (no http://)")
        self.entry_target.grid(row=2, column=0, padx=16, pady=(0,8), sticky="ew")
        self.entry_target.bind("<Return>", lambda e: self.start_scan())

        _label(sb, "Ports (comma, empty = defaults):", muted=True).grid(row=3, column=0, padx=16, pady=(8,0), sticky="w")
        self.entry_ports = ctk.CTkEntry(sb, placeholder_text="80,443,8080,8443,22,53,4444,6667,9001,1337")
        self.entry_ports.grid(row=4, column=0, padx=16, pady=(0,8), sticky="ew")

        self.var_tor = ctk.BooleanVar(value=True)
        self.sw_tor = ctk.CTkSwitch(sb, text="Route via TOR (SOCKS5h)", variable=self.var_tor)
        self.sw_tor.grid(row=5, column=0, padx=16, pady=(8,0), sticky="w")

        tor_frame = _card(sb); tor_frame.grid(row=6, column=0, padx=16, pady=(8,8), sticky="ew")
        tor_frame.grid_columnconfigure(1, weight=1)
        _label(tor_frame, "TOR Host:", muted=True).grid(row=0, column=0, padx=8, pady=6, sticky="w")
        self.entry_tor_host = ctk.CTkEntry(tor_frame); self.entry_tor_host.insert(0, "127.0.0.1")
        self.entry_tor_host.grid(row=0, column=1, padx=8, pady=6, sticky="ew")
        _label(tor_frame, "TOR Port:", muted=True).grid(row=1, column=0, padx=8, pady=6, sticky="w")
        self.entry_tor_port = ctk.CTkEntry(tor_frame); self.entry_tor_port.insert(0, "9050")
        self.entry_tor_port.grid(row=1, column=1, padx=8, pady=6, sticky="ew")

        # Profile/options
        opt = _card(sb); opt.grid(row=7, column=0, padx=16, pady=(8,8), sticky="ew")
        _label(opt, "Scan profile:", muted=True).grid(row=0, column=0, padx=8, pady=6, sticky="w")
        self.profile = ctk.StringVar(value="Balanced")
        for i, name in enumerate(["Stealth","Balanced","Aggressive"]):
            ctk.CTkRadioButton(opt, text=name, variable=self.profile, value=name).grid(row=0, column=i+1, padx=8, pady=6, sticky="w")
        self.var_banner = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(opt, text="Read TCP banners", variable=self.var_banner).grid(row=1, column=0, columnspan=2, padx=8, pady=(0,8), sticky="w")

        _btn_primary(sb, "🛡️ Start scan", self.start_scan).grid(row=8, column=0, padx=16, pady=(8,8), sticky="ew")
        _btn_subtle(sb, "💾 Export JSON", self.export_json).grid(row=9, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "🧠 Load model", self._reload_model).grid(row=10, column=0, padx=16, pady=(0,16), sticky="ew")

        # Main area
        main = _card(self); main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(main, fg_color=BG_CARD); header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
        header.grid_columnconfigure(0, weight=1)
        header.grid_columnconfigure(1, weight=0)

        self.var_summary = ctk.StringVar(value="Ready.")
        lbl_sum = _label(header, "", muted=False); lbl_sum.configure(textvariable=self.var_summary)
        lbl_sum.grid(row=0, column=0, padx=6, pady=6, sticky="w")

        self.var_ai = ctk.StringVar(value="AI/ML: —")
        lbl_ai = _label(header, "", muted=True); lbl_ai.configure(textvariable=self.var_ai)
        lbl_ai.grid(row=0, column=1, padx=6, pady=6, sticky="e")

        # Tabs
        body = ctk.CTkFrame(main, fg_color=BG_CARD)
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)

        _style_ttk_dark()
        self.nb = ttk.Notebook(body); self.nb.grid(row=0, column=0, sticky="nsew")

        self.tab_reasons = ctk.CTkFrame(self.nb, fg_color=BG_CARD); self.nb.add(self.tab_reasons, text="Signals/Reasons"); self._init_reasons(self.tab_reasons)
        self.tab_dns = ctk.CTkFrame(self.nb, fg_color=BG_CARD); self.nb.add(self.tab_dns, text="DNS"); self._init_dns(self.tab_dns)
        self.tab_ports = ctk.CTkFrame(self.nb, fg_color=BG_CARD); self.nb.add(self.tab_ports, text="Ports"); self._init_ports(self.tab_ports)
        self.tab_http = ctk.CTkFrame(self.nb, fg_color=BG_CARD); self.nb.add(self.tab_http, text="HTTP"); self._init_http(self.tab_http)
        self.tab_tls = ctk.CTkFrame(self.nb, fg_color=BG_CARD); self.nb.add(self.tab_tls, text="TLS"); self._init_tls(self.tab_tls)
        self.tab_fav = ctk.CTkFrame(self.nb, fg_color=BG_CARD); self.nb.add(self.tab_fav, text="Favicon"); self._init_fav(self.tab_fav)

        status = _card(self); status.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
        self.txt_status = _textbox(status, height=70)
        self.txt_status.grid(row=0, column=0, padx=12, pady=10, sticky="ew")
        self._status("Use only where authorized. Results are heuristic/ML-based.")

        self.report = None

    def _try_load_model(self):
        if self.model_path and joblib is not None and Path(self.model_path).exists():
            try:
                self.model_bundle = joblib.load(self.model_path)
            except Exception:
                self.model_bundle = None

    def _reload_model(self):
        path = filedialog.askopenfilename(filetypes=[("Joblib","*.joblib"),("All","*.*")])
        if not path:
            return
        try:
            self.model_bundle = joblib.load(path)
            messagebox.showinfo("ML", f"Model loaded: {path}")
        except Exception as e:
            messagebox.showerror("ML", f"Could not load model: {e}")

    # --- helpers ---
    def _status(self, msg):
        self.txt_status.insert("end", f"• {msg}\n")
        self.txt_status.see("end")

    # --- Tab builders ---
    def _init_reasons(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        cols = ("Points", "Reason")
        self.tree_reasons = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        self.tree_reasons.heading("Points", text="Points")
        self.tree_reasons.heading("Reason", text="Reason")
        self.tree_reasons.column("Points", width=80, anchor="center")
        self.tree_reasons.column("Reason", width=900, anchor="w")
        self.tree_reasons.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree_reasons.yview)
        self.tree_reasons.configure(yscrollcommand=vsb.set); vsb.grid(row=0, column=1, sticky="ns")

    def _init_dns(self, parent):
        parent.grid_columnconfigure(1, weight=1)
        self.var_a = ctk.StringVar(value="—"); self.var_aaaa = ctk.StringVar(value="—"); self.var_ptr = ctk.StringVar(value="—"); self.var_ttl = ctk.StringVar(value="—")
        _label(parent, "A:", muted=True).grid(row=0, column=0, padx=8, pady=6, sticky="w")
        _label(parent, "", muted=False).configure(textvariable=self.var_a); ctk.CTkLabel(parent, textvariable=self.var_a, text="").grid(row=0, column=1, padx=8, pady=6, sticky="w")
        _label(parent, "AAAA:", muted=True).grid(row=1, column=0, padx=8, pady=6, sticky="w")
        ctk.CTkLabel(parent, textvariable=self.var_aaaa, text="").grid(row=1, column=1, padx=8, pady=6, sticky="w")
        _label(parent, "PTR:", muted=True).grid(row=2, column=0, padx=8, pady=6, sticky="w")
        ctk.CTkLabel(parent, textvariable=self.var_ptr, text="").grid(row=2, column=1, padx=8, pady=6, sticky="w")
        _label(parent, "TTL(s):", muted=True).grid(row=3, column=0, padx=8, pady=6, sticky="w")
        ctk.CTkLabel(parent, textvariable=self.var_ttl, text="").grid(row=3, column=1, padx=8, pady=6, sticky="w")
        _label(parent, "Notes:", muted=True).grid(row=4, column=0, padx=8, pady=6, sticky="nw")
        self.txt_dns_err = _textbox(parent, height=110); self.txt_dns_err.grid(row=4, column=1, sticky="ew", padx=8, pady=8)

    def _init_ports(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        cols = ("Port", "Open", "Banner (truncated)")
        self.tree_ports = ttk.Treeview(parent, columns=cols, show="headings", selectmode="none")
        self.tree_ports.heading("Port", text="Port")
        self.tree_ports.heading("Open", text="Open")
        self.tree_ports.heading("Banner (truncated)", text="Banner (truncated)")
        self.tree_ports.column("Port", width=100, anchor="center")
        self.tree_ports.column("Open", width=100, anchor="center")
        self.tree_ports.column("Banner (truncated)", width=700, anchor="w")
        self.tree_ports.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _init_http(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        cols = ("Status", "URL", "Server", "CT", "Location", "Body-Len")
        self.tree_http = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        for name, width, anchor in [("Status",60,"center"),("URL",520,"w"),("Server",200,"w"),("CT",140,"w"),("Location",240,"w"),("Body-Len",90,"e")]:
            self.tree_http.heading(name, text=name)
            self.tree_http.column(name, width=width, anchor=anchor)
        self.tree_http.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    def _init_tls(self, parent):
        parent.grid_columnconfigure(1, weight=1)
        labels = ["Version", "Cipher", "Subject", "Issuer", "Valid from", "Valid until", "Days", "Self-signed?"]
        self.tls_vars = [ctk.StringVar(value="—") for _ in labels]
        for i, lab in enumerate(labels):
            _label(parent, f"{lab}:", muted=True).grid(row=i, column=0, padx=8, pady=4, sticky="w")
            val = ctk.CTkLabel(parent, textvariable=self.tls_vars[i], text=""); val.grid(row=i, column=1, padx=8, pady=4, sticky="w")
        _label(parent, "Errors/Notes:", muted=True).grid(row=len(labels), column=0, padx=8, pady=6, sticky="nw")
        self.txt_tls_err = _textbox(parent, height=90); self.txt_tls_err.grid(row=len(labels), column=1, sticky="ew", padx=8, pady=8)

    def _init_fav(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        cols = ("Channel", "Hash", "Status/Error")
        self.tree_fav = ttk.Treeview(parent, columns=cols, show="headings", selectmode="none")
        for col, w in zip(cols, (160, 220, 520)):
            self.tree_fav.heading(col, text=col)
            self.tree_fav.column(col, width=w, anchor="w")
        self.tree_fav.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    # --- Actions ---
    def start_scan(self):
        raw_target = (self.entry_target.get() or "").strip()
        ports_txt = (self.entry_ports.get() or "").strip()
        if not raw_target:
            messagebox.showwarning("Missing input", "Please enter a domain or IP.")
            return
        ports = []
        if ports_txt:
            for x in ports_txt.split(","):
                x = x.strip()
                if x:
                    try: ports.append(int(x))
                    except: pass
        if not ports:
            ports = DEFAULT_PORTS[:]
        use_tor = bool(self.var_tor.get())
        tor_host = (self.entry_tor_host.get() or "127.0.0.1").strip()
        try:
            tor_port = int(self.entry_tor_port.get() or "9050")
        except:
            tor_port = 9050
        prof = self.profile.get()
        do_banner = bool(self.var_banner.get())
        self.var_summary.set("Scanning…")
        cleaned = sanitize_target(raw_target)
        self._status(f"Start scan — Target: {cleaned} (from '{raw_target}') · TOR={'on' if use_tor else 'off'} ({tor_host}:{tor_port}) · Profile={prof}")
        th = threading.Thread(target=self._scan_thread, args=(raw_target, sorted(set(ports)), use_tor, tor_host, tor_port, prof, do_banner), daemon=True)
        th.start()

    def _scan_thread(self, raw_target, ports, use_tor, tor_host, tor_port, profile, do_banner):
        try:
            rep = analyze(raw_target, ports, use_tor=use_tor, tor_host=tor_host, tor_port=tor_port, profile=profile, do_banner=do_banner)
            self.report = rep
            self._render_report(rep)
            self._status("Scan finished.")
        except Exception as e:
            self.var_summary.set(f"Error: {e}")
            self._status(f"Error: {e}")

    def _render_report(self, rep):
        self.var_summary.set(rep.get("summary",""))

        # ML probability (if model available), else heuristic
        if self.model_bundle:
            p, why = ml_predict(self.model_bundle, rep)
            self.var_ai.set(f"ML: {p*100:.1f}% risk · Top features: {', '.join(why) if why else 'n/a'}")
        else:
            p, _, why = ai_probability_heuristic(rep)
            self.var_ai.set(f"Heuristic: {p*100:.1f}% risk · Drivers: {', '.join(why) if why else '—'}")

        # Reasons
        for i in self.tree_reasons.get_children(): self.tree_reasons.delete(i)
        for r in rep.get("reasons", []):
            self.tree_reasons.insert("", "end", values=(f"{r['points']:+.1f}", r["reason"]))

        # DNS
        dns = rep.get("dns", {})
        self.var_a.set(", ".join(dns.get("a_records", [])) or "—")
        self.var_aaaa.set(", ".join(dns.get("aaaa_records", [])) or "—")
        self.var_ptr.set(dns.get("ptr") or "—")
        self.var_ttl.set(", ".join(str(t) for t in dns.get("ttls", []) if t is not None) or "—")
        self.txt_dns_err.delete("1.0","end")
        notes = []
        if dns.get("errors"):
            notes.extend(dns["errors"])
        if dns.get("note"):
            notes.append(dns["note"])
        if notes:
            self.txt_dns_err.insert("end", "\n".join(notes))

        # Ports + banners
        for i in self.tree_ports.get_children(): self.tree_ports.delete(i)
        for p in sorted(rep.get("ports",{}).keys()):
            v = rep["ports"][p]
            banner = rep.get("banners",{}).get(p, "")
            self.tree_ports.insert("", "end", values=(p, "✅ open" if v.get("open") else "—", banner))

        # HTTP
        for i in self.tree_http.get_children(): self.tree_http.delete(i)
        for h in rep.get("http", []):
            if "error" in h:
                self.tree_http.insert("", "end", values=("ERR", h.get("url",""), h.get("error"), "", "", ""))
            else:
                self.tree_http.insert("", "end",
                    values=(h.get("status_code"), h.get("url",""), (h.get("server") or ""), (h.get("content_type") or ""), (h.get("location") or ""), h.get("body_len",0)))

        # TLS
        tls = rep.get("tls",{})
        self.txt_tls_err.delete("1.0","end")
        if "error" in tls:
            self.txt_tls_err.insert("end", tls.get("error"))
        else:
            for i, val in enumerate([
                tls.get("tls_version") or "—",
                str(tls.get("cipher") or "—"),
                tls.get("subject") or "—",
                tls.get("issuer") or "—",
                tls.get("not_before") or "—",
                tls.get("not_after") or "—",
                str(tls.get("valid_days") if tls.get("valid_days") is not None else "—"),
                "Yes" if tls.get("self_signed_like") else "No"
            ]):
                self.tls_vars[i].set(val)

        # Favicon
        for i in self.tree_fav.get_children(): self.tree_fav.delete(i)
        for chan, data in rep.get("favicon", {}).items():
            if isinstance(data, dict):
                self.tree_fav.insert("", "end", values=(chan, data.get("hash","—"), data.get("error") or data.get("status")))
            else:
                self.tree_fav.insert("", "end", values=(chan, "—", str(data)))

    def export_json(self):
        if not self.report:
            messagebox.showinfo("No result", "Please run a scan first.")
            return
        try:
            path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")], initialfile=f"null_inspector_{self.report['target']}.json")
            if not path:
                return
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.report, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Export", f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))


# ------------------------------
#  CLI / Entry
# ------------------------------

def main():
    parser = argparse.ArgumentParser(description="null_inspector + ML (GUI/CLI) with optional TOR routing")
    parser.add_argument("--nogui", action="store_true", help="no GUI: CLI scan and JSON to stdout")
    parser.add_argument("--tor", action="store_true", help="scan via TOR (SOCKS5h)")
    parser.add_argument("--tor-host", default="127.0.0.1")
    parser.add_argument("--tor-port", default="9050")
    parser.add_argument("--profile", default="Balanced", choices=["Stealth","Balanced","Aggressive"])
    parser.add_argument("--no-banner", action="store_true", help="do not read TCP banners")
    parser.add_argument("--train", action="store_true", help="start ML training (see --data, --out, --algo)")
    parser.add_argument("--data", default="", help="path to training data folder (labels.csv + reports/)")
    parser.add_argument("--out", default="models/null_inspector_model.joblib", help="path for saved model (joblib)")
    parser.add_argument("--algo", default="logreg", choices=["logreg","lgbm"], help="ML algorithm")
    parser.add_argument("--favicon-db", default="", help="path to favicon hash DB (JSON)")
    parser.add_argument("target", nargs="?", help="optional: target (only for --nogui)")
    parser.add_argument("--ports", help="comma-separated list of ports", default="")
    args = parser.parse_args()

    if args.train:
        train_model(args.data, args.out, args.algo)
        return

    if args.favicon_db:
        load_favicon_db(args.favicon_db)

    if args.nogui:
        if not args.target:
            print("Please provide a target. Example: --nogui example.com --ports 80,443,8080 --tor")
            return
        # parse ports
        ports = []
        if args.ports:
            for x in args.ports.split(","):
                x = x.strip()
                if x:
                    try: ports.append(int(x))
                    except: pass
        if not ports:
            ports = DEFAULT_PORTS[:]
        rep = analyze(args.target, sorted(set(ports)),
                      use_tor=args.tor,
                      tor_host=args.tor_host,
                      tor_port=int(args.tor_port),
                      profile=args.profile,
                      do_banner=(not args.no_banner))

        # If a saved model exists at default path, use it
        if Path("models/null_inspector_model.joblib").exists() and joblib is not None:
            model_bundle = joblib.load("models/null_inspector_model.joblib")
            p, why = ml_predict(model_bundle, rep)
            rep["ml_probability"] = p
            rep["ml_top_features"] = why
        else:
            p, _, why = ai_probability_heuristic(rep)
            rep["ai_probability"] = p
            rep["ai_top_factors"] = why

        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return

    if ctk is None:
        print("customtkinter not available. Install with: pip install customtkinter")
        return

    app = NullInspectorMLApp()
    app.mainloop()


if __name__ == "__main__":
    main()