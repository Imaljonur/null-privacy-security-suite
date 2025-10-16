#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FastNews GUI (stable build, no function removals)
- Presets: DE/AT, International, Mixed
- Per-source selection dialog ("Choose sources…") + "Use selected"
- Manual RSS override (highest priority)
- Include/Exclude filters
- Stream & Once
- Save JSON
- Stop button with stop_event
- Optimizations: canonical_url (dedupe trackers), title_key (near-dup titles), MAX_ROWS trim
"""

from __future__ import annotations
import os
import sys
import json
import time
import queue
import asyncio
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Safe deps
def _require(mod: str, pip_name: Optional[str] = None):
    try:
        return __import__(mod)
    except ImportError as e:
        name = pip_name or mod
        msg = (f"Missing dependency: {name}\n"
               f"Install with: pip install {name}\n\n{e}")
        print(msg, file=sys.stderr)
        raise

ctk = _require("customtkinter")
feedparser = _require("feedparser")
dateutil = _require("dateutil")
httpx = _require("httpx")
from dateutil import parser as dateparse

# =========== Theme & constants ===========
ACCENT        = "#00FF88"
BG_DARK       = "#0B0F10"
BG_CARD       = "#12171A"
FG_TEXT       = "#D7E0E6"
FG_MUTED      = "#8FA3AD"
BORDER        = "#1D252B"

MAX_ROWS = 500  # keep UI responsive

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

# =========== Utils ===========
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s: return None
    try:
        dt = dateparse.parse(s)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def iso(dt: Optional[datetime]) -> str:
    return dt.astimezone(timezone.utc).isoformat() if dt else ""

def _hash12(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]

def canonical_url(u: str) -> str:
    if not u:
        return u
    sp = urlsplit(u)
    keep = [(k, v) for k, v in parse_qsl(sp.query, keep_blank_values=True)
            if not k.lower().startswith(("utm_", "fbclid", "gclid", "mc_cid", "mc_eid"))]
    return urlunsplit((sp.scheme, sp.netloc.lower(), sp.path, urlencode(keep, doseq=True), ""))

def title_key(title: str) -> str:
    t = (title or "").strip().lower()
    t = " ".join(t.replace("—", "-").replace("–", "-").split())
    return _hash12(t)

# =========== Data model ===========
@dataclass
class Item:
    id: str
    source: str
    title: str
    url: str
    published: datetime
    provider: str

# =========== Defaults & Presets ===========
DEFAULT_RSS: List[str] = [
    "https://www.tagesschau.de/xml/rss2",
    "https://www.zdf.de/rss/zdf/nachrichten",
    "https://rss.orf.at/news.xml",
    "https://www.derstandard.at/rss/2000004/topnews",
    "https://newsfeed.zeit.de/all",
    "https://www.spiegel.de/schlagzeilen/index.rss",
    "https://feeds.bbci.co.uk/news/rss.xml",
    "https://www.theguardian.com/world/rss",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://rss.dw.com/rdf/rss-en-all",
    "https://www.euronews.com/rss?level=theme&name=news",
    "https://feeds.bbci.co.uk/news/rss.xml",
    "https://www.theguardian.com/world/rss",
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.theguardian.com/world/rss",
    "https://feeds.washingtonpost.com/rss/world",
    "https://rss.nytimes.com/services/xml/rss/nyt/World.xml",
    "http://rss.cnn.com/rss/edition_world.rss",
    "http://feeds.skynews.com/feeds/rss/world.xml",
    "https://www.ft.com/world?format=rss",
    "https://rss.dw.com/rdf/rss-en-all",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://www.euronews.com/rss?level=theme&name=news"
]

PRESETS: Dict[str, List[str]] = {
    "DE/AT": [
        "https://www.tagesschau.de/xml/rss2",
        "https://www.zdf.de/rss/zdf/nachrichten",
        "https://rss.orf.at/news.xml",
        "https://www.derstandard.at/rss/2000004/topnews",
        "https://www.derstandard.at/rss/international",
        "https://newsfeed.zeit.de/all",
        "https://www.spiegel.de/schlagzeilen/index.rss",
        "https://www.faz.net/rss/aktuell/",
        "https://rss.sueddeutsche.de/rss/Topthemen"
    ],
    "International": [
        "https://feeds.bbci.co.uk/news/world/rss.xml",
        "https://www.theguardian.com/world/rss",
        "https://feeds.washingtonpost.com/rss/world",
        "https://rss.nytimes.com/services/xml/rss/nyt/World.xml",
        "http://rss.cnn.com/rss/edition_world.rss",
        "http://feeds.skynews.com/feeds/rss/world.xml",
        "https://www.ft.com/world?format=rss",
        "https://rss.dw.com/rdf/rss-en-all",
        "https://www.aljazeera.com/xml/rss/all.xml",
        "https://www.euronews.com/rss?level=theme&name=news"
    ],
    "Mixed": [
        "https://www.tagesschau.de/xml/rss2",
        "https://www.zdf.de/rss/zdf/nachrichten",
        "https://rss.orf.at/news.xml",
        "https://www.derstandard.at/rss/2000004/topnews",
        "https://newsfeed.zeit.de/all",
        "https://www.spiegel.de/schlagzeilen/index.rss",
        "https://feeds.bbci.co.uk/news/rss.xml",
        "https://www.theguardian.com/world/rss",
        "https://www.aljazeera.com/xml/rss/all.xml",
        "https://rss.dw.com/rdf/rss-en-all",
        "https://www.euronews.com/rss?level=theme&name=news"
        ,
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.theguardian.com/world/rss",
    "https://feeds.washingtonpost.com/rss/world",
    "https://rss.nytimes.com/services/xml/rss/nyt/World.xml",
    "http://rss.cnn.com/rss/edition_world.rss",
    "http://feeds.skynews.com/feeds/rss/world.xml",
    "https://www.ft.com/world?format=rss",
    "https://rss.dw.com/rdf/rss-en-all",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://www.euronews.com/rss?level=theme&name=news"
    ]
}

FEED_LABELS: Dict[str, str] = {
    # DE/AT
    "https://www.tagesschau.de/xml/rss2": "Tagesschau (ARD)",
    "https://www.zdf.de/rss/zdf/nachrichten": "ZDFheute",
    "https://rss.orf.at/news.xml": "ORF News",
    "https://www.derstandard.at/rss/2000004/topnews": "DER STANDARD Top",
    "https://www.derstandard.at/rss/international": "DER STANDARD International",
    "https://newsfeed.zeit.de/all": "ZEIT ONLINE (All)",
    "https://www.spiegel.de/schlagzeilen/index.rss": "SPIEGEL Schlagzeilen",
    "https://www.faz.net/rss/aktuell/": "FAZ Aktuell",
    "https://rss.sueddeutsche.de/rss/Topthemen": "Süddeutsche Topthemen",
    # International
    "https://feeds.bbci.co.uk/news/rss.xml": "BBC News",
    "https://www.theguardian.com/world/rss": "The Guardian World",
    "https://www.aljazeera.com/xml/rss/all.xml": "Al Jazeera English",
    "https://rss.dw.com/rdf/rss-en-all": "DW English",
    "https://www.euronews.com/rss?level=theme&name=news": "Euronews",
    "https://www.theguardian.com/world/rss": "The Guardian World",

    "https://feeds.bbci.co.uk/news/world/rss.xml": "BBC World",
    "https://www.theguardian.com/world/rss": "The Guardian World",
    "https://feeds.washingtonpost.com/rss/world": "Washington Post World",
    "https://rss.nytimes.com/services/xml/rss/nyt/World.xml": "NYT World",
    "http://rss.cnn.com/rss/edition_world.rss": "CNN World",
    "http://feeds.skynews.com/feeds/rss/world.xml": "Sky News World",
    "https://www.ft.com/world?format=rss": "Financial Times World",
    "https://rss.dw.com/rdf/rss-en-all": "DW English",
    "https://www.aljazeera.com/xml/rss/all.xml": "Al Jazeera English",
    "https://www.euronews.com/rss?level=theme&name=news": "Euronews",
}

# =========== Providers ===========
async def fetch_rss(client: httpx.AsyncClient, url: str) -> List[Item]:
    try:
        r = await client.get(url, timeout=10)
        r.raise_for_status()
        feed = feedparser.parse(r.content)
        src_title = feed.feed.get("title", "RSS")
        out: List[Item] = []
        for e in feed.entries[:60]:
            link = (e.get("link") or e.get("id") or "").strip()
            title = (e.get("title") or "").strip()
            if not link or not title: 
                continue
            published = parse_dt(e.get("published") or e.get("updated") or e.get("pubDate"))
            out.append(Item(
                id=_hash12(link or (src_title + "|" + title)),
                source=src_title,
                title=title,
                url=link,
                published=published or now_utc(),
                provider="RSS"
            ))
        return out
    except Exception:
        return []

async def fetch_newsapi(client: httpx.AsyncClient, q: str) -> List[Item]:
    api = os.getenv("NEWSAPI_KEY")
    if not api: return []
    params = {"apiKey": api, "pageSize": 50, "language": "en"}
    if q: params["q"] = q
    url = "https://newsapi.org/v2/top-headlines?" + urlencode(params)
    try:
        r = await client.get(url, timeout=12)
        r.raise_for_status()
        data = r.json()
        out: List[Item] = []
        for a in data.get("articles", [])[:60]:
            out.append(Item(
                id=_hash12((a.get("url") or a.get("title","")).strip()),
                source=(a.get("source", {}) or {}).get("name") or "NewsAPI",
                title=(a.get("title") or "").strip(),
                url=(a.get("url") or "").strip(),
                published=parse_dt(a.get("publishedAt")) or now_utc(),
                provider="NewsAPI"
            ))
        return out
    except Exception:
        return []

async def fetch_newsdata(client: httpx.AsyncClient, q: str) -> List[Item]:
    api = os.getenv("NEWSDATA_API_KEY")
    if not api: return []
    params = {"apiKey": api, "language":"en", "size":50}
    if q: params["q"] = q
    url = "https://newsdata.io/api/1/latest?" + urlencode(params)
    try:
        r = await client.get(url, timeout=12)
        r.raise_for_status()
        data = r.json()
        out: List[Item] = []
        for a in data.get("results", [])[:60]:
            out.append(Item(
                id=_hash12((a.get("link") or a.get("title","")).strip()),
                source=(a.get("source_id") or a.get("source") or "NewsData"),
                title=(a.get("title") or "").strip(),
                url=(a.get("link") or "").strip(),
                published=parse_dt(a.get("pubDate")) or now_utc(),
                provider="NewsData"
            ))
        return out
    except Exception:
        return []

async def fetch_thenewsapi(client: httpx.AsyncClient, q: str) -> List[Item]:
    api = os.getenv("THENEWSAPI_KEY")
    if not api: return []
    params = {"api_token": api, "language":"en", "limit":50}
    if q: params["search"] = q
    url = "https://api.thenewsapi.com/v1/news/top?" + urlencode(params)
    try:
        r = await client.get(url, timeout=12)
        r.raise_for_status()
        data = r.json()
        out: List[Item] = []
        for a in data.get("data", [])[:60]:
            out.append(Item(
                id=_hash12((a.get("url") or a.get("title","")).strip()),
                source=(a.get("source") or "TheNewsAPI"),
                title=(a.get("title") or "").strip(),
                url=(a.get("url") or "").strip(),
                published=parse_dt(a.get("published_at")) or now_utc(),
                provider="TheNewsAPI"
            ))
        return out
    except Exception:
        return []

async def fetch_gnews(client: httpx.AsyncClient, q: str) -> List[Item]:
    api = os.getenv("GNEWS_API_KEY")
    if not api: return []
    params = {"token": api, "lang":"en", "max":50}
    if q: params["q"] = q
    url = "https://gnews.io/api/v4/top-headlines?" + urlencode(params)
    try:
        r = await client.get(url, timeout=12)
        r.raise_for_status()
        data = r.json()
        out: List[Item] = []
        for a in data.get("articles", [])[:60]:
            out.append(Item(
                id=_hash12((a.get("url") or a.get("title","")).strip()),
                source=((a.get("source") or {}) or {}).get("name") or "GNews",
                title=(a.get("title") or "").strip(),
                url=(a.get("url") or "").strip(),
                published=parse_dt(a.get("publishedAt")) or now_utc(),
                provider="GNews"
            ))
        return out
    except Exception:
        return []

def _match_keywords(title: str, include: List[str], exclude: List[str]) -> bool:
    t = (title or "").lower()
    if include and not any(k in t for k in include):
        return False
    if exclude and any(k in t for k in exclude):
        return False
    return True

async def collect_once(q: str, rss_list: List[str], include: List[str], exclude: List[str], use_apis: bool, limit: int) -> List[Item]:
    items: Dict[str, Item] = {}
    transport = httpx.AsyncHTTPTransport(retries=2)
    async with httpx.AsyncClient(transport=transport, follow_redirects=True, headers={"User-Agent":"fastnews/1.0"}) as client:
        tasks: List[asyncio.Task] = []
        for url in (rss_list or DEFAULT_RSS):
            tasks.append(asyncio.create_task(fetch_rss(client, url)))
        if use_apis:
            tasks.append(asyncio.create_task(fetch_newsapi(client, q)))
            tasks.append(asyncio.create_task(fetch_newsdata(client, q)))
            tasks.append(asyncio.create_task(fetch_thenewsapi(client, q)))
            tasks.append(asyncio.create_task(fetch_gnews(client, q)))
        for coro in asyncio.as_completed(tasks):
            batch = await coro
            for it in batch:
                if not _match_keywords(it.title, include, exclude):
                    continue
                key = canonical_url(it.url) or it.id
                if key not in items:
                    items[key] = it
    out = list(items.values())
    out.sort(key=lambda i: i.published, reverse=True)
    return out[:limit] if limit else out

async def stream_collect(q: str, rss_list: List[str], include: List[str], exclude: List[str], use_apis: bool,
                         duration: int, poll: float, on_item, stop_event: threading.Event | None = None) -> None:
    seen: set[str] = set()
    title_seen: set[str] = set()
    start = time.time()
    transport = httpx.AsyncHTTPTransport(retries=2)
    async with httpx.AsyncClient(transport=transport, follow_redirects=True, headers={"User-Agent":"fastnews/1.0"}) as client:
        async def run_one(fn, *a):
            try:
                batch = await fn(*a)
                return batch
            except Exception:
                return []
        while (stop_event is None or not stop_event.is_set()) and (time.time() - start < max(1, duration)):
            tasks: List[asyncio.Task] = []
            for url in (rss_list or DEFAULT_RSS):
                tasks.append(asyncio.create_task(run_one(fetch_rss, client, url)))
            if use_apis:
                tasks.append(asyncio.create_task(run_one(fetch_newsapi, client, q)))
                tasks.append(asyncio.create_task(run_one(fetch_newsdata, client, q)))
                tasks.append(asyncio.create_task(run_one(fetch_thenewsapi, client, q)))
                tasks.append(asyncio.create_task(run_one(fetch_gnews, client, q)))
            for fut in asyncio.as_completed(tasks, timeout=5):
                if stop_event is not None and stop_event.is_set():
                    break
                batch = await fut
                for it in batch:
                    if not _match_keywords(it.title, include, exclude):
                        continue
                    key = canonical_url(it.url) or it.id
                    if key in seen:
                        continue
                    tkey = title_key(it.title)
                    if tkey in title_seen:
                        continue
                    seen.add(key)
                    title_seen.add(tkey)
                    on_item(it)
            if stop_event is not None and stop_event.is_set():
                break
            await asyncio.sleep(max(1.5, poll))

# =========== GUI ===========
class NullNewsGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        _theme_setup()
        self.title("∅ NullNews")
        self.geometry("1240x780")
        self.configure(fg_color=BG_DARK)

        # state
        self._worker: Optional[threading.Thread] = None
        self._stop_event: threading.Event = threading.Event()
        self._queue: "queue.Queue[Item|tuple]" = queue.Queue()
        self._items: Dict[str, Item] = {}
        self._source_vars: Dict[str, tk.BooleanVar] = {}

        # layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._tick_queue()

    # Sidebar
    def _build_sidebar(self):
        sb = _card(self)
        sb.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        sb.grid_columnconfigure(0, weight=1)

        _title(sb, "∅ NullNews").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        _label(sb, "Fast RSS + optional APIs", muted=True).grid(row=1, column=0, padx=16, pady=(0,14), sticky="w")

        _btn_primary(sb, "Start Stream", self._start_stream).grid(row=2, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "Fetch Once", self._fetch_once).grid(row=3, column=0, padx=16, pady=(0,16), sticky="ew")
        _btn_subtle(sb, "Stop", self._stop).grid(row=4, column=0, padx=16, pady=(0,16), sticky="ew")
        _btn_subtle(sb, "Save JSON…", self._save_json).grid(row=5, column=0, padx=16, pady=(0,16), sticky="ew")

        self.status = _label(sb, "Idle", muted=True)
        self.status.grid(row=6, column=0, padx=16, pady=(8,12), sticky="w")

        _label(sb, "Tip: set API keys as env vars.", muted=True).grid(row=7, column=0, padx=16, pady=(0,6), sticky="w")

    # Main
    def _build_main(self):
        main = _card(self)
        main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        for i in range(6):
            main.grid_columnconfigure(i, weight=1)
        main.grid_rowconfigure(3, weight=1)

        top = ctk.CTkFrame(main, fg_color=BG_CARD)
        top.grid(row=0, column=0, columnspan=6, sticky="ew", padx=12, pady=(12,6))
        for i in range(12):
            top.grid_columnconfigure(i, weight=1)

        _label(top, "Keywords (include)").grid(row=0, column=0, padx=6, pady=6, sticky="e")
        self.e_inc = ctk.CTkEntry(top, placeholder_text="e.g. election,earthquake")
        self.e_inc.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

        _label(top, "Exclude").grid(row=0, column=2, padx=6, pady=6, sticky="e")
        self.e_exc = ctk.CTkEntry(top, placeholder_text="e.g. sports,gossip")
        self.e_exc.grid(row=0, column=3, padx=6, pady=6, sticky="ew")

        _label(top, "Duration (s)").grid(row=0, column=4, padx=6, pady=6, sticky="e")
        self.e_duration = ctk.CTkEntry(top); self.e_duration.insert(0, "60")
        self.e_duration.grid(row=0, column=5, padx=6, pady=6, sticky="ew")

        _label(top, "Poll (s)").grid(row=0, column=6, padx=6, pady=6, sticky="e")
        self.e_poll = ctk.CTkEntry(top); self.e_poll.insert(0, "6")
        self.e_poll.grid(row=0, column=7, padx=6, pady=6, sticky="ew")

        _label(top, "Limit (once)").grid(row=0, column=8, padx=6, pady=6, sticky="e")
        self.e_limit = ctk.CTkEntry(top); self.e_limit.insert(0, "40")
        self.e_limit.grid(row=0, column=9, padx=6, pady=6, sticky="ew")

        self.var_use_api = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(top, text="Use APIs (env keys)", variable=self.var_use_api).grid(row=0, column=10, padx=6, pady=6, sticky="w")

        # Endless-Option (scan without time limit)
        self.var_endless = tk.BooleanVar(value=False)

        def _toggle_endless():
            try:
                self.e_duration.configure(state=("disabled" if self.var_endless.get() else "normal"))
            except Exception:
                pass

        ctk.CTkCheckBox(
            top, text="Endless", variable=self.var_endless, command=_toggle_endless
        ).grid(row=0, column=11, padx=6, pady=6, sticky="w")

        _label(top, "Source set").grid(row=1, column=0, padx=6, pady=6, sticky="e")
        self.opt_set = ctk.CTkOptionMenu(top, values=list(PRESETS.keys()))
        self.opt_set.set("Mixed")
        self.opt_set.grid(row=1, column=1, padx=6, pady=6, sticky="w")

        self.var_use_selection = tk.BooleanVar(value=False)
        _btn_subtle(top, "Choose sources…", self._open_sources_dialog).grid(row=1, column=2, padx=6, pady=6, sticky="w")
        ctk.CTkCheckBox(top, text="Use selected", variable=self.var_use_selection).grid(row=1, column=3, padx=6, pady=6, sticky="w")

        _label(top, "RSS (comma, optional)").grid(row=2, column=0, padx=6, pady=6, sticky="e")
        self.e_rss = ctk.CTkEntry(top, placeholder_text="Leave empty to use preset/selection")
        self.e_rss.grid(row=2, column=1, columnspan=9, padx=6, pady=6, sticky="ew")

        metrics = ctk.CTkFrame(main, fg_color=BG_CARD)
        metrics.grid(row=1, column=0, columnspan=6, sticky="ew", padx=12, pady=(0,8))
        for i in range(6): metrics.grid_columnconfigure(i, weight=1)

        self.lbl_count = _label(metrics, "Items: 0"); self.lbl_count.grid(row=0, column=0, padx=8, pady=8, sticky="w")
        self.lbl_prov  = _label(metrics, "Providers: RSS"); self.lbl_prov.grid(row=0, column=1, padx=8, pady=8, sticky="w")
        self.lbl_last  = _label(metrics, "Last: —"); self.lbl_last.grid(row=0, column=2, padx=8, pady=8, sticky="w")

        table = ctk.CTkFrame(main, fg_color=BG_CARD)
        table.grid(row=3, column=0, columnspan=6, sticky="nsew", padx=12, pady=(0,12))
        table.grid_columnconfigure(0, weight=1)
        table.grid_rowconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background=BG_CARD, foreground=FG_TEXT, fieldbackground=BG_CARD, rowheight=24, borderwidth=0)
        style.map("Treeview", background=[("selected", "#1E2935")], foreground=[("selected", FG_TEXT)])
        style.configure("Treeview.Heading", background=BG_CARD, foreground=FG_MUTED)

        cols = ("time", "provider", "source", "title")
        self.tree = ttk.Treeview(table, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("time", text="Time (UTC)", command=lambda: self._sort_tree("time", False))
        self.tree.heading("provider", text="Provider", command=lambda: self._sort_tree("provider", False))
        self.tree.heading("source", text="Source", command=lambda: self._sort_tree("source", False))
        self.tree.heading("title", text="Title", command=lambda: self._sort_tree("title", False))
        self.tree.column("time", width=160, anchor="w")
        self.tree.column("provider", width=90, anchor="w")
        self.tree.column("source", width=200, anchor="w")
        self.tree.column("title", width=700, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Double-1>", self._open_selected)

    # Helpers
    def _parse_list(self, s: str) -> List[str]:
        return [x.strip().lower() for x in (s or "").split(",") if x.strip()]

    def _providers_text(self) -> str:
        provs = ["RSS"]
        if self.var_use_api.get():
            for k in ("NEWSAPI_KEY","NEWSDATA_API_KEY","THENEWSAPI_KEY","GNEWS_API_KEY"):
                if os.getenv(k):
                    provs.append(k.split("_")[0])
        try:
            preset = self.opt_set.get()
        except Exception:
            preset = "Mixed"
        sel_hint = " (selected)" if self.var_use_selection.get() else ""
        return "Providers: " + ", ".join(sorted(set(provs))) + f"  | Set: {preset}" + sel_hint

    def _selected_sources(self) -> List[str]:
        return [u for u, var in self._source_vars.items() if var.get()]

    def _current_rss(self) -> List[str]:
        # 1) Manual override
        custom = [u.strip() for u in (self.e_rss.get() or "").split(",") if u.strip()]
        if custom: return custom
        # 2) Selected sources
        if self.var_use_selection.get():
            sel = self._selected_sources()
            if sel: return sel
        # 3) Preset
        try:
            name = self.opt_set.get()
        except Exception:
            name = "Mixed"
        return PRESETS.get(name, DEFAULT_RSS)

    def _open_sources_dialog(self):
        win = ctk.CTkToplevel(self)
        win.title("Choose sources")
        win.geometry("560x520")
        # Modal & on top
        win.transient(self); win.lift()
        try: win.attributes("-topmost", True)
        except Exception: pass
        win.grab_set()
        try: win.focus_force()
        except Exception: pass
        def _drop_topmost():
            try: win.attributes("-topmost", False)
            except Exception: pass
        self.after(200, _drop_topmost)

        frm = ctk.CTkScrollableFrame(win, fg_color=BG_CARD, corner_radius=10)
        frm.pack(fill="both", expand=True, padx=12, pady=12)

        ctrl = ctk.CTkFrame(win, fg_color=BG_CARD)
        ctrl.pack(fill="x", padx=12, pady=(0,12))

        # Union of all feeds
        all_urls = set()
        for v in PRESETS.values(): all_urls.update(v)
        all_urls.update(DEFAULT_RSS)

        def _select_all():
            for u in all_urls:
                self._source_vars.setdefault(u, tk.BooleanVar(value=True)).set(True)
            _refresh_checks()

        def _select_none():
            for u in all_urls:
                self._source_vars.setdefault(u, tk.BooleanVar(value=False)).set(False)
            _refresh_checks()

        _btn_subtle(ctrl, "Select all", _select_all).pack(side="left", padx=6, pady=6)
        _btn_subtle(ctrl, "Select none", _select_none).pack(side="left", padx=6, pady=6)
        _btn_primary(ctrl, "Apply & Close", win.destroy).pack(side="right", padx=6, pady=6)

        try:
            preset_name = self.opt_set.get()
        except Exception:
            preset_name = "Mixed"
        default_sel = set(PRESETS.get(preset_name, DEFAULT_RSS))

        def _refresh_checks():
            for w in frm.winfo_children(): w.destroy()
            groups = [
                ("DE/AT", [u for u in all_urls if u in PRESETS.get("DE/AT", [])]),
                ("International", [u for u in all_urls if u in PRESETS.get("International", [])]),
                ("Other", [u for u in all_urls if (u not in PRESETS.get("DE/AT", []) and u not in PRESETS.get("International", []))]),
            ]
            for gname, urls in groups:
                if not urls: continue
                ctk.CTkLabel(frm, text=gname, text_color=ACCENT).pack(anchor="w", padx=8, pady=(10,4))
                for u in sorted(set(urls)):
                    var = self._source_vars.setdefault(u, tk.BooleanVar(value=(u in default_sel)))
                    label = FEED_LABELS.get(u, u)
                    ctk.CTkCheckBox(frm, text=label, variable=var).pack(anchor="w", padx=16, pady=2)

        _refresh_checks()

    def _append_item(self, it: Item):
        key = it.url or it.id
        if key in self._items: return
        self._items[key] = it
        ts = iso(it.published).replace("T"," ").replace("+00:00","Z")
        self.tree.insert("", "end", iid=key, values=(ts, it.provider, it.source, it.title))
        self._update_metrics()
        # Trim oldest rows
        children = self.tree.get_children()
        if len(children) > MAX_ROWS:
            self.tree.delete(children[0: len(children) - MAX_ROWS])

    def _open_selected(self, event=None):
        sel = self.tree.selection()
        if not sel: return
        key = sel[0]
        it = self._items.get(key)
        if not it: return
        import webbrowser
        try:
            webbrowser.open(it.url, new=2, autoraise=True)
        except Exception as e:
            messagebox.showerror("Open URL failed", str(e))

    def _clear_table(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)

    def _update_metrics(self):
        self.lbl_count.configure(text=f"Items: {len(self._items)}")
        self.lbl_prov.configure(text=self._providers_text())
        self.lbl_last.configure(text=f"Last: {datetime.utcnow().strftime('%H:%M:%S')}Z")


    def _sort_tree(self, col: str, reverse: bool):
        # Collect current values for the given column
        rows = [(self.tree.set(iid, col), iid) for iid in self.tree.get_children("")]
        if col == "time":
            from datetime import datetime
            def parse_iso(s: str):
                try:
                    return datetime.strptime(s, "%Y-%m-%d %H:%M:%SZ")
                except Exception:
                    return datetime.min
            rows.sort(key=lambda t: parse_iso(t[0]), reverse=reverse)
        else:
            rows.sort(key=lambda t: (t[0] or "").lower(), reverse=reverse)
        for idx, (_, iid) in enumerate(rows):
            self.tree.move(iid, "", idx)
        # Toggle sort order on next click
        self.tree.heading(col, command=lambda: self._sort_tree(col, not reverse))

    # Actions
    def _start_stream(self):
        # cleanup stale worker if any
        if self._worker is not None and not self._worker.is_alive():
            self._worker = None
        if self._worker and self._worker.is_alive():
            messagebox.showinfo("Already running", "Stream is already running.")
            return
        self._clear_table()
        self._items.clear()
        include = self._parse_list(self.e_inc.get())
        exclude = self._parse_list(self.e_exc.get())
        rss = self._current_rss()
        use_apis = bool(self.var_use_api.get())

        try:
            duration = int(self.e_duration.get() or "60")
        except ValueError:
            duration = 60

        # Endless enforces a practically infinite duration
        if getattr(self, "var_endless", None) and self.var_endless.get():
            duration = 10**12  # ~31700 years
        try:
            poll = float(self.e_poll.get() or "6")
        except ValueError:
            poll = 6.0

        self._stop_event.clear()
        self.status.configure(text="Streaming…")
        self.title("∅ NullNews — streaming")

        def worker():
            try:
                asyncio.run(stream_collect(",".join(include), rss, include, exclude, use_apis, duration, poll, self._queue.put, self._stop_event))
            except Exception as e:
                self._queue.put(("__error__", str(e)))
            finally:
                self._queue.put(("__done__", None))

        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _fetch_once(self):
        if self._worker and self._worker.is_alive():
            messagebox.showinfo("Busy", "Please stop the running task first.")
            return
        self._clear_table()
        self._items.clear()
        include = self._parse_list(self.e_inc.get())
        exclude = self._parse_list(self.e_exc.get())
        rss = self._current_rss()
        use_apis = bool(self.var_use_api.get())

        try:
            limit = int(self.e_limit.get() or "40")
        except ValueError:
            limit = 40

        self.status.configure(text="Fetching once…")
        self.title("∅ NullNews — fetching…")

        def worker():
            try:
                items = asyncio.run(collect_once(",".join(include), rss, include, exclude, use_apis, limit))
                self._queue.put(("__batch__", items))
            except Exception as e:
                self._queue.put(("__error__", str(e)))
            finally:
                self._queue.put(("__done__", None))

        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _stop(self):
        try:
            self._stop_event.set()
            if self._worker and self._worker.is_alive():
                self._worker.join(timeout=1.0)
            if self._worker and not self._worker.is_alive():
                self._worker = None
        except Exception:
            pass
        self.status.configure(text="Stopped")
        self.title("∅ NullNews — stopped")

    def _save_json(self):
        if not self._items:
            messagebox.showinfo("Nothing to save", "No items collected yet.")
            return
        path = filedialog.asksaveasfilename(title="Save JSON", defaultextension=".json",
                                            filetypes=[("JSON","*.json"), ("All files","*.*")])
        if not path: return
        out = []
        for it in sorted(self._items.values(), key=lambda i: i.published, reverse=True):
            out.append({
                "source": it.source,
                "provider": it.provider,
                "title": it.title,
                "url": it.url,
                "published": iso(it.published),
            })
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("Saved", f"Saved {len(out)} items to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    # Queue pump
    def _tick_queue(self):
        try:
            while True:
                obj = self._queue.get_nowait()
                if isinstance(obj, tuple) and obj and obj[0] == "__batch__":
                    items: List[Item] = obj[1]
                    for it in items:
                        self._append_item(it)
                    self.status.configure(text=f"Fetched {len(items)} items.")
                    self.title("∅ NullNews")
                elif isinstance(obj, tuple) and obj and obj[0] == "__error__":
                    self.status.configure(text=f"Error: {obj[1]}")
                elif isinstance(obj, tuple) and obj and obj[0] == "__done__":
                    self._worker = None
                    self.status.configure(text="Idle")
                    self.title("∅ NullNews")
                elif isinstance(obj, Item):
                    self._append_item(obj)
                    self.status.configure(text="Streaming… (items updating)")
        except queue.Empty:
            pass
        self.after(120, self._tick_queue)

# Entrypoint
def main():
    app = NullNewsGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
