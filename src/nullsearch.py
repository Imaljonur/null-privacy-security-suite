# null_search_ctk.py
# UI unified on CustomTkinter (Design wie bei deinen anderen Tools)
# LOGIC UNCHANGED – only UI/widgets/layout adjusted.
# Additionally: More stable TOR IP check + robust check_tor_connection()

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import requests
from bs4 import BeautifulSoup
import webbrowser
import random
import time
import re
import customtkinter as ctk
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

def canonicalize_url(url: str) -> str:
    try:
        pu = urlparse(url)
    except Exception:
        return url
    scheme = pu.scheme.lower() or "http"
    netloc = pu.netloc.lower()
    path = pu.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    fragment = ""
    qs = parse_qs(pu.query, keep_blank_values=False)
    drop_keys = {"utm_source","utm_medium","utm_campaign","utm_term","utm_content","utm_id","gclid","fbclid","mc_cid","mc_eid","igshid","msclkid","ref","ref_src"}
    qs = {k:v for k,v in qs.items() if k not in drop_keys}
    query = urlencode([(k, v2) for k,vs in qs.items() for v2 in vs])
    return urlunparse((scheme, netloc, path, pu.params, query, fragment))

def dedupe_results(results):
    seen = set()
    out = []
    for r in results:
        cu = canonicalize_url(r.get("url",""))
        key = (cu, r.get("title","").strip().lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out

def extract_site_filter(query: str):
    parts = query.split()
    for t in parts:
        if t.startswith("site:") and len(t) > 5:
            return t[5:]
    return None

from urllib.parse import urlparse, parse_qs, unquote, urljoin

def unwrap_ddg_link(href: str) -> str:
    """Remove DuckDuckGo redirect (/l/?uddg=...) and return real target URL."""
    if not href:
        return href
    try:
        p = urlparse(href)
    except Exception:
        return href
    # make relative DDG links absolute
    if not p.netloc:
        href = urljoin("https://duckduckgo.com", href)
        p = urlparse(href)
    # detect DDG redirect
    if p.netloc.endswith("duckduckgo.com") and p.path.startswith("/l/"):
        qs = parse_qs(p.query)
        target = qs.get("uddg") or qs.get("rut")
        if target and target[0]:
            return unquote(target[0])
    return href


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

# =====================
# Global variables (LOGIC)
# =====================
BLOCK_HINTS = set()
SCORING_OK = 0
SCORING_BLOCK = 0
SEARCH_LOCK = threading.Lock()
stop_event = threading.Event()
search_running = False  # guarded by SEARCH_LOCK
current_query = ""
current_engine = ""
current_page = 0
timeout_seconds = 10

# Widgets werden später gesetzt
root = None
results_box = None
search_entry = None
search_engine_var = None
relevance_var = None
date_filter_var = None
more_button = None

# =====================
# User-Agents (LOGIC)
# =====================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

MINIMAL_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# =====================
# Tor-Session & IP (LOGIK)
# =====================
def get_tor_ip():
    """Robuster IP-Check: mehrere Plaintext-Endpunkte + Fallback-Extraktion aus HTML."""
    import re as _re
    proxies = {
        'http':  'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    headers = {"Accept": "text/plain"}
    endpoints = [
        "https://api.ipify.org",   # plain text
        "https://ifconfig.me/ip",  # plain text
        "https://icanhazip.com",   # plain text
        "https://ident.me"         # plain text
    ]
    for url in endpoints:
        try:
            r = requests.get(url, proxies=proxies, headers=headers, timeout=10)
            txt = (r.text or "").strip()
            if _re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", txt) or (":" in txt):
                return txt
        except requests.RequestException:
            continue
    # Fallback: IP aus HTML extrahieren (z. B. 403-Seiten)
    try:
        r = requests.get("https://ifconfig.me", proxies=proxies, timeout=10)
        html = r.text or ""
        m4 = _re.search(r"(?:\d{1,3}\.){3}\d{1,3}", html)
        if m4:
            return m4.group(0)
        m6 = _re.search(r"[0-9a-fA-F:]{2,}", html)
        if m6 and ":" in m6.group(0):
            return m6.group(0)
    except requests.RequestException:
        pass
    return "unknown"

def get_tor_session(engine="DuckDuckGo"):
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    session.headers.update(MINIMAL_HEADERS)
    session.headers["User-Agent"] = random.choice(USER_AGENTS)
    return session

def tor_get(url, engine="DuckDuckGo", **kwargs):
    time.sleep(random.uniform(0.3, 0.7))
    session = get_tor_session(engine)
    return session.get(url, timeout=timeout_seconds, **kwargs)

def tor_post(url, engine="DuckDuckGo", data=None, **kwargs):
    time.sleep(random.uniform(0.3, 0.7))
    session = get_tor_session(engine)
    return session.post(url, data=data, timeout=timeout_seconds, **kwargs)

# =====================
# Check Tor connection (LOGIC – more robust)
# =====================
def check_tor_connection():
    """Use check.torproject.org API for robust Tor detection."""
    try:
        r = tor_get("https://check.torproject.org/api/ip")
        return '"IsTor":true' in r.text
    except Exception:
        return False

# =====================
# Search engines (LOGIC)
# =====================

def _compact_spaces(s: str) -> str:
    import re as _re
    return _re.sub(r"\s+", " ", (s or "").strip())

def _strip_urls(s: str) -> str:
    import re as _re
    return _re.sub(r"https?://\S+", "", s or "").strip()

def _clean_title_generic(raw: str) -> str:
    import re as _re
    t = _strip_urls(raw or "")
    t = _compact_spaces(t)
    if "|" in t:
        parts = [p.strip() for p in t.split("|") if p.strip()]
        if parts:
            parts.sort(key=lambda x: sum(c.isalpha() for c in x), reverse=True)
            t = parts[0]
    if "›" in t:
        parts = [p.strip() for p in t.split("›") if p.strip()]
        if parts:
            t = parts[-1]
    t = _re.sub(r"^[a-z0-9_-]{3,}\s+", "", t)
    return _compact_spaces(t)

def _clean_snippet_generic(raw: str) -> str:
    return _compact_spaces(_strip_urls(raw))

def perform_duckduckgo_search(query, page=0):
    try:
        url = "https://html.duckduckgo.com/html/"
        data = {"q": query, "s": str(page * 30)}
        sel = date_filter_var.get()
        if sel == "New (24h)":
            data["df"] = "d"
        elif sel == "Last week":
            data["df"] = "w"
        elif sel == "Last year":
            data["df"] = "y"

        r = tor_post(url, data=data)
        soup = BeautifulSoup(r.text or "", "html.parser")

        results = []
        for card in soup.select("div.result"):
            a = card.select_one("a.result__a") or card.select_one("a[href]")
            if not a:
                continue
            href = (a.get("href") or "").strip()
            if not href:
                continue
            title = _clean_title_generic(a.get_text(" ", strip=True))
            snip = ""
            s_node = card.select_one(".result__snippet, .result__extras__snippet") or card.select_one("p")
            if s_node:
                snip = _clean_snippet_generic(s_node.get_text(" ", strip=True))
            results.append({
                "title": title,
                "url": unwrap_ddg_link(href),
                "snippet": snip,
                "score": 0
            })

        if not results:
            for a in soup.select("a.result__a, a[data-testid='result-title-a'], a[href]"):
                href = (a.get("href") or "").strip()
                if not href or "duckduckgo.com/y.js" in href:
                    continue
                title = _clean_title_generic(a.get_text(" ", strip=True))
                if not title:
                    continue
                results.append({
                    "title": title,
                    "url": unwrap_ddg_link(href),
                    "snippet": "",
                    "score": 0
                })

        return dedupe_results(results)
    except Exception:
        return []

def perform_brave_search(query, page=0):
    try:
        tbs = ""
        sel = date_filter_var.get()
        if sel == "New (24h)":
            tbs = "&tbs=qdr:d"
        elif sel == "Last week":
            tbs = "&tbs=qdr:w"
        elif sel == "Last year":
            tbs = "&tbs=qdr:y"

        url = f"https://search.brave.com/search?q={query}&offset={page*20}&source=web{tbs}"
        r = tor_get(url)
        soup = BeautifulSoup(r.text or "", "html.parser")

        results = []
        for block in soup.select("div.snippet, div.card, div.result, li.snippet, div#results > div"):
            a = block.select_one("a[href]")
            if not a:
                continue
            href = (a.get("href") or "").strip()
            if not href.startswith("http"):
                continue

            title = a.get("title") or a.get_text(" ", strip=True)
            title = _clean_title_generic(title)

            s_node = block.select_one("p, .snippet-content, .description, .snippet-description")
            snip = _clean_snippet_generic(s_node.get_text(" ", strip=True)) if s_node else ""

            if not title:
                continue

            results.append({
                "title": title,
                "url": unwrap_ddg_link(href),
                "snippet": snip,
                "score": 0
            })

        return dedupe_results(results)
    except Exception:
        return []

def perform_onion_search(query, page=0):
    return perform_duckduckgo_search(query + " site:.onion", page)

# =====================
# >>> ADDITIVE: neue Engines (Gov & Scholarly)
# =====================
def perform_gov_search(query, page=0):
    # AT, DE, EU, UK, US – offizielle Seiten
    gov_filter = " (site:.gv.at OR site:.de OR site:.eu OR site:.gov.uk OR site:.gov OR site:whitehouse.gov)"
    return perform_duckduckgo_search(query + gov_filter, page)

def perform_scholarly_search(query, page=0):
    # Studies/Authorities: NCBI/PubMed/NIH/WHO/CDC/EMA/ECDC
    sci_filter = (
        " (site:ncbi.nlm.nih.gov OR site:pubmed.ncbi.nlm.nih.gov OR site:nih.gov"
        " OR site:who.int OR site:cdc.gov OR site:ema.europa.eu OR site:ecdc.europa.eu)"
    )
    return perform_duckduckgo_search(query + sci_filter, page)

# =====================
# Content scoring (LOGIC)
# =====================


# Dedicated pooled session only for content scoring (keeps GUI/search untouched)
_scoring_session = None
def get_scoring_session():
    global _scoring_session
    if _scoring_session is None:
        s = requests.Session()
        s.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        s.headers.update(MINIMAL_HEADERS)
        _scoring_session = s
    return _scoring_session

def fetch_and_score(url, query):
    # Fallback, falls synonyms-Modul fehlt
    try:
        from synonyms import get_synonyms  # optionales, externes Modul
    except ImportError:
        def get_synonyms(word: str):
            # Minimal-fallback: nur das Wort selbst (kein Crash mehr, aber deterministisch)
            return [word]

    try:
        # Unwrap DDG redirect if present
        url = unwrap_ddg_link(url)

        # Build per-request headers (do not mutate session default headers)
        req_headers = dict(MINIMAL_HEADERS)
        req_headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
            "Upgrade-Insecure-Requests": "1",
        })

        # Use pooled scoring session with exponential backoff
        s = get_scoring_session()
        delay = random.uniform(0.25, 0.6)
        resp = None
        for _ in range(4):
            try:
                resp = s.get(url, headers=req_headers, timeout=timeout_seconds, allow_redirects=True)
                if resp.status_code in (429, 500, 502, 503, 504):
                    time.sleep(delay)
                    delay = min(delay * 2, 6.0)
                    continue
                break
            except requests.RequestException:
                time.sleep(delay)
                delay = min(delay * 2, 6.0)

        if not resp or resp.status_code != 200:
            try:
                BLOCK_HINTS.add(url)
                globals()['SCORING_BLOCK'] = globals().get('SCORING_BLOCK',0)+1
                if 'root' in globals() and root:
                    total = globals().get('SCORING_OK',0) + globals().get('SCORING_BLOCK',0)
                    root.after(0, lambda: root.title(f"∅NullSearch – scored {globals().get('SCORING_OK',0)}/{total}"))
            except Exception:
                pass
            return 0

        text = resp.text or ""
        if "captcha" in text.lower():
            try:
                BLOCK_HINTS.add(url)
                globals()['SCORING_BLOCK'] = globals().get('SCORING_BLOCK',0)+1
                if 'root' in globals() and root:
                    total = globals().get('SCORING_OK',0) + globals().get('SCORING_BLOCK',0)
                    root.after(0, lambda: root.title(f"∅NullSearch – scored {globals().get('SCORING_OK',0)}/{total}"))
            except Exception:
                pass
            return 0

        # Extract visible text and score by synonyms
        text = BeautifulSoup(text, "html.parser").get_text(" ", strip=True).lower()

        total_score = 0
        for word in query.split():
            syns = get_synonyms(word)
            for syn in syns:
                weight = 3 if syn == word else 1
                # important: use real \b word boundaries
                total_score += weight * len(re.findall(rf"\b{re.escape(syn)}\b", text, re.I))

        try:
            globals()['SCORING_OK'] = globals().get('SCORING_OK',0)+1
            if 'root' in globals() and root:
                total = globals().get('SCORING_OK',0) + globals().get('SCORING_BLOCK',0)
                root.after(0, lambda: root.title(f"∅NullSearch – scored {globals().get('SCORING_OK',0)}/{total}"))
        except Exception:
            pass

        return total_score

    except Exception:
        return 0

def live_content_relevance_parallel(results, query, engine, max_workers=6):
    subset = results[:15]
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fetch_and_score, r["url"], query): r for r in subset}
        for fut in as_completed(futures):
            if stop_event.is_set():
                break
            r = futures[fut]
            try:
                content = fut.result()
            except Exception:
                content = 0
            r["content_score"] = content
            meta = r.get("score", 0)
            r["score"] = int(0.6*meta + 0.4*content)
            # inkrementelles Update
            sorted_list = sorted(results, key=lambda x: x.get("score", 0), reverse=True)
            root.after(0, lambda lst=sorted_list: display_results(lst, append=False, scoring=True))

    # Brave-Fallback wie vorher
    if (not stop_event.is_set()) and engine == "BraveSearch" and sum(1 for r in results if r.get("score",0) > 0) < 3:
        ddg_results = perform_duckduckgo_search(query, 0)
        more = ddg_results[:15]
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(fetch_and_score, r["url"], query): r for r in more}
            for fut in as_completed(futures):
                if stop_event.is_set():
                    break
                r = futures[fut]
                try:
                    score = fut.result()
                except Exception:
                    score = 0
                r["score"] = score
                results.append(r)
                sorted_list = sorted(results, key=lambda x: x.get("score", 0), reverse=True)
                root.after(0, lambda lst=sorted_list: display_results(lst, append=False, scoring=True))

    return sorted(results, key=lambda x: x.get("score", 0), reverse=True)

# =====================
# Local re-ranking (LOGIC)
# =====================
def score_by_metadata(item, query):
    title = (item.get("title") or "").lower()
    snip  = (item.get("snippet") or "").lower()
    url   = (item.get("url") or "").lower()

    words = re.findall(r"\w{3,}", query.lower())

    def count_hits(text):
        return sum(len(re.findall(rf"\b{re.escape(w)}\b", text)) for w in words)

    s = 0
    s += 5 * count_hits(title)      # Titel wichtig
    s += 2 * count_hits(snip)       # Snippet mittel
    s += 1 * count_hits(url)        # URL leicht

    if query.lower() in title:
        s += 8

    bad_hints = ("/tag/", "/category/", "/labels/", "/opinion/", "/archive/")
    if any(h in url for h in bad_hints):
        s -= 3

    good_hints = ("official", "docs", "whitepaper")
    if any(h in url for h in good_hints):
        s += 2

    trusted = ("whitehouse.gov", ".gov", ".edu", ".gv.at", ".admin.ch", ".eu")
    if any(t in url for t in trusted):
        s += 3

    return s

def rerank_results_locally(results, query):
    for r in results:
        r["score"] = score_by_metadata(r, query)
    return sorted(results, key=lambda x: x.get("score", 0), reverse=True)

# =====================
# Suche starten/stoppen (LOGIK)
# =====================
def request_stop():
    global search_running
    stop_event.set()
    with SEARCH_LOCK:
        search_running = False
    results_box.configure(state="normal")
    results_box.insert("end", "⏹ Search aborted.")
    results_box.configure(state="disabled")

def start_search(new_search=True):
    global search_running, current_query, current_engine, current_page
    with SEARCH_LOCK:
        if search_running:
            messagebox.showinfo("Info", "⏳ A search is already running — please wait.")
            return
        search_running = True
    stop_event.clear()

    query = search_entry.get().strip()
    engine = search_engine_var.get()
    if not query:
        with SEARCH_LOCK:
            search_running = False
        return
    if not check_tor_connection():
        with SEARCH_LOCK:
            search_running = False
        messagebox.showerror("Tor error", "Tor connection not available!")
        return
    if new_search:
        current_page = 0
        current_query = query
        current_engine = engine

    results_box.configure(state="normal")
    results_box.delete("1.0", "end")
    results_box.insert("end", "🔍 Searching...")
    results_box.configure(state="disabled")

    threading.Thread(target=run_search, args=(query, engine, current_page), daemon=True).start()

def run_search(query, engine, page):
    if stop_event.is_set():
        return
    ip = get_tor_ip()
    root.after(0, lambda: results_box.configure(state="normal"))
    root.after(0, lambda: results_box.insert("end", f"🌍 TOR IP: {ip}"))
    root.after(0, lambda: results_box.configure(state="disabled"))
    if stop_event.is_set():
        return

    if engine == "DuckDuckGo":
        results = perform_duckduckgo_search(query, page)
    elif engine == "BraveSearch":
        results = perform_brave_search(query, page)
    elif engine == "OnionSearch":
        results = perform_onion_search(query, page)
    elif engine == "GovSearch":  # <<< additive
        results = perform_gov_search(query, page)
    elif engine == "Scholarly":  # <<< additive
        results = perform_scholarly_search(query, page)
    else:
        results = perform_duckduckgo_search(query, page)

    if stop_event.is_set():
        return

    root.after(0, lambda: results_box.configure(state="normal"))
    root.after(0, lambda: results_box.insert("end", "✅ Search finished."))
    root.after(0, lambda: results_box.configure(state="disabled"))

    if stop_event.is_set():
        return

    if relevance_var.get():
        ranked = rerank_results_locally(results, query)
        root.after(0, lambda lst=ranked: display_results(lst, append=False, scoring=False))
        final_sorted = live_content_relevance_parallel(ranked, query, engine)
        root.after(0, lambda lst=final_sorted: display_results(lst, append=False, scoring=False))
    else:
        root.after(0, lambda: display_results(results))

    global search_running
    with SEARCH_LOCK:
        search_running = False

# =====================
# Anzeige (UI)
# =====================
def display_results(results, append=False, scoring=False):
    if stop_event.is_set() and not scoring:
        return

    def _cx(s: str) -> str:
        import re as _re
        return _re.sub(r"\s+", " ", (s or "").strip())

    results_box.configure(state="normal")
    if not append:
        results_box.delete("1.0", "end")

    if not isinstance(results, list):
        results = []

    for res in results:
        title   = _cx(res.get("title", ""))
        snippet = _cx(res.get("snippet", ""))
        url     = res.get("url", "")

        rv = bool(relevance_var.get()) if (relevance_var is not None) else False
        score_display = f"{res.get('score', 0)} ⭐ " if rv else ""
        block_tag = " 🔒" if ('BLOCK_HINTS' in globals() and res.get('url') in BLOCK_HINTS) else ""

        results_box.insert("end", f"{score_display}{title}{block_tag}\n")
        if snippet:
            results_box.insert("end", f"{snippet}\n")
        results_box.insert("end", url + "\n\n")

        start = results_box.search(url, "1.0", tk.END)
        if start:
            end = f"{start}+{len(url)}c"
            tag_name = f"url_{url}"
            results_box.tag_add(tag_name, start, end)
            results_box.tag_config(tag_name, foreground=FG_MUTED, underline=True)
            results_box.tag_bind(tag_name, "<Button-1>", lambda e, u=url: webbrowser.open(u))

    results_box.configure(state="disabled")
    if not scoring and not stop_event.is_set():
        more_button.grid()

def load_more():
    global current_page, search_running
    if stop_event.is_set():
        return
    with SEARCH_LOCK:
        if search_running:
            return
        current_page += 1
        search_running = True
    start_search(new_search=False)

# =====================
# Settings (UI)
# =====================
def open_settings():
    global timeout_seconds
    win = ctk.CTkToplevel(root)
    win.title("Settings")
    win.geometry("320x160")
    win.configure(fg_color=BG_CARD)
    win.grid_columnconfigure(0, weight=1)

    _title(win, "⚙ Settings").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
    row = _card(win); row.grid(row=1, column=0, padx=16, pady=(4,16), sticky="ew")
    _label(row, "Timeout (sec)", muted=True).grid(row=0, column=0, padx=10, pady=(10,6), sticky="w")
    timeout_var = tk.IntVar(value=timeout_seconds)
    ent = ctk.CTkEntry(row, textvariable=timeout_var); ent.grid(row=1, column=0, padx=10, pady=(0,10), sticky="w")

    def save_settings():
        global timeout_seconds
        try:
            timeout_seconds = int(timeout_var.get())
        except:
            timeout_seconds = 10
        win.destroy()

    _btn_primary(row, "Save", save_settings).grid(row=2, column=0, padx=10, pady=(0,10), sticky="w")

# =====================
# GUI BOOTSTRAP (CustomTkinter Layout wie bei den anderen Tools)
# =====================
def main():
    global root, results_box, search_entry, search_engine_var, relevance_var, date_filter_var, more_button

    _theme_setup()
    root = ctk.CTk()
    root.title("∅NullSearch – Tor Web Search")
    root.geometry("1100x720")

    # Shortcuts
    root.bind('<Return>', lambda e: start_search())
    root.bind('<Control-l>', lambda e: (search_entry.focus_set(), search_entry.select_range(0,'end')))
    root.configure(fg_color=BG_DARK)

    # Layout: Sidebar | Main
    root.grid_columnconfigure(0, weight=0)
    root.grid_columnconfigure(1, weight=1)
    root.grid_rowconfigure(0, weight=1)
    root.grid_rowconfigure(1, weight=0)

    # --- Sidebar ---
    sb = _card(root)
    sb.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
    sb.grid_columnconfigure(0, weight=1)

    _title(sb, "∅ NullSearch").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
    _label(sb, "Search via Tor (DDG/Brave/Onion)", muted=True).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

    # Query Card
    qcard = _card(sb); qcard.grid(row=2, column=0, padx=16, pady=(0,12), sticky="ew")
    qcard.grid_columnconfigure(0, weight=1)

    _label(qcard, "Query:", muted=True).grid(row=0, column=0, padx=10, pady=(10,4), sticky="w")
    search_entry = ctk.CTkEntry(qcard, placeholder_text="e.g., privacy friendly browser")
    search_entry.grid(row=1, column=0, padx=10, pady=(0,10), sticky="ew")

    # Engine + Filter Card
    fcard = _card(sb); fcard.grid(row=3, column=0, padx=16, pady=(0,12), sticky="ew")
    for i in range(3): fcard.grid_columnconfigure(i, weight=1)

    _label(fcard, "Search engine:", muted=True).grid(row=0, column=0, padx=10, pady=(10,4), sticky="w")
    search_engine_var = tk.StringVar(value="DuckDuckGo")
    engine_menu = ctk.CTkOptionMenu(
        fcard, variable=search_engine_var,
        values=["DuckDuckGo","BraveSearch","OnionSearch","GovSearch","Scholarly"]  # <<< additive
    )
    engine_menu.grid(row=1, column=0, padx=10, pady=(0,10), sticky="ew")

    _label(fcard, "Date filter:", muted=True).grid(row=0, column=1, padx=10, pady=(10,4), sticky="w")
    date_filter_var = tk.StringVar(value="All")
    date_menu = ctk.CTkOptionMenu(fcard, variable=date_filter_var, values=["All","New (24h)","Last week","Last year"])
    date_menu.grid(row=1, column=1, padx=10, pady=(0,10), sticky="ew")

    relevance_var = tk.BooleanVar(value=False)
    rel_check = ctk.CTkCheckBox(fcard, text="Content relevance (live scoring)", variable=relevance_var)
    rel_check.grid(row=1, column=2, padx=10, pady=(0,10), sticky="w")

    # Actions
    _btn_primary(sb, "🔎 Search", start_search).grid(row=4, column=0, padx=16, pady=(0,8), sticky="ew")
    _btn_subtle(sb, "⏹ Stop", request_stop).grid(row=5, column=0, padx=16, pady=(0,8), sticky="ew")
    _btn_subtle(sb, "⚙ Settings", open_settings).grid(row=6, column=0, padx=16, pady=(0,16), sticky="ew")

    # --- Main Card ---
    main = _card(root)
    main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
    main.grid_columnconfigure(0, weight=1)
    main.grid_rowconfigure(1, weight=1)

    header = ctk.CTkFrame(main, fg_color=BG_CARD)
    header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
    header.grid_columnconfigure(0, weight=1)
    _label(header, "Results", muted=True).grid(row=0, column=0, sticky="w")

    body = ctk.CTkFrame(main, fg_color=BG_CARD)
    body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
    body.grid_columnconfigure(0, weight=1)
    body.grid_rowconfigure(0, weight=1)

    # Textbox für Results (klickbare Links via Text-Tags)
    results_box = ctk.CTkTextbox(body, fg_color="#0E1417", text_color=FG_TEXT, wrap="word")
    results_box.grid(row=0, column=0, sticky="nsew")
    results_box.configure(state="disabled")

    # Scrollbar
    vsb = ttk.Scrollbar(body, orient="vertical", command=lambda *a: results_box.yview(*a))
    results_box.configure(yscrollcommand=vsb.set)
    vsb.grid(row=0, column=1, sticky="ns")

    # More Button (unten)
    more_bar = _card(root)
    more_bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
    more_bar.grid_columnconfigure(0, weight=1)
    more_button = _btn_primary(more_bar, "Load more", load_more)
    more_button.grid(row=0, column=0, padx=12, pady=10, sticky="w")

    # ttk-Style dunkel
    style = ttk.Style()
    try: style.theme_use("clam")
    except: pass
    style.configure(".", background=BG_CARD, fieldbackground=BG_CARD, foreground=FG_TEXT)

    # Referenzen in globals speichern
    globals().update(dict(
        root=root,
        results_box=results_box,
        search_entry=search_entry,
        search_engine_var=search_engine_var,
        relevance_var=relevance_var,
        date_filter_var=date_filter_var,
        more_button=more_button
    ))

    root.mainloop()

if __name__ == "__main__":
    main()
