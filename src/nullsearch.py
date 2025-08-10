
import customtkinter as ctk
import requests
from bs4 import BeautifulSoup
import urllib.parse
import random
import threading
import webbrowser
from tkinter import ttk

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

# =========================
#  ORIGINAL CONSTANTS/LOGIC (UNCHANGED)
# =========================
TOR_PROXY = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36",
]

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "de-DE,de;q=0.8,en-US;q=0.5,en;q=0.3",
        "Referer": "https://duckduckgo.com/",
        "Connection": "keep-alive",
    }

def clean_ddg_link(href):
    if "/l/?" in href and "uddg=" in href:
        parsed = urllib.parse.urlparse(href)
        qs = urllib.parse.parse_qs(parsed.query)
        if "uddg" in qs:
            return urllib.parse.unquote(qs["uddg"][0])
    return href

def extract_domain(url):
    try:
        d = urllib.parse.urlparse(url).netloc
        if d.startswith("www."):
            d = d[4:]
        return d
    except Exception:
        return url

def get_site_title(url):
    try:
        r = requests.get(url, headers=get_random_headers(), proxies=TOR_PROXY, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No <title> found"
        return title
    except Exception as e:
        return f"Error: {e}"

def search_duckduckgo_onion(query: str, max_results: int = 40):
    results = []
    seen_links = set()
    q = urllib.parse.quote_plus(query)
    base = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html/"
    per_page = 10
    pages = (max_results + per_page - 1) // per_page
    session = requests.Session()
    session.proxies.update(TOR_PROXY)
    session.headers.update(get_random_headers())
    session.cookies.clear()
    for page in range(pages):
        url = f"{base}?q={q}&s={page*per_page}"
        try:
            resp = session.get(url, timeout=20)
            soup = BeautifulSoup(resp.text, "html.parser")
            for r in soup.select(".result"):
                a = r.find("a", class_="result__a")
                snippet = r.find("a", class_="result__snippet")
                title = a.get_text(strip=True) if a else ""
                href = a.get('href') if a else ""
                real_link = clean_ddg_link(href)
                if not title or not real_link or real_link in seen_links:
                    continue
                seen_links.add(real_link)
                snippet_text = snippet.get_text(strip=True) if snippet else ""
                results.append({
                    'title': title,
                    'href': real_link,
                    'snippet': snippet_text,
                    'domain': extract_domain(real_link)
                })
                if len(results) >= max_results:
                    return results
        except Exception as e:
            print(f"Error fetching DuckDuckGo (onion): {e}")
            break
    return results

# =========================
#  NEW GUI ONLY — table + details
# =========================
class NullSearchApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        _theme_setup()
        self.title("∅nullsearch advanced – DuckDuckGo (.onion)")
        self.geometry("1200x800")
        self.configure(fg_color=BG_DARK)

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        # Sidebar
        sb = _card(self); sb.grid(row=0, column=0, sticky="nsw", padx=(16,8), pady=16)
        sb.grid_columnconfigure(0, weight=1)
        _title(sb, "∅ nullsearch").grid(row=0, column=0, padx=16, pady=(16,4), sticky="w")
        _label(sb, "TOR · Filter · Sortierung · Meta", muted=True).grid(row=1, column=0, padx=16, pady=(0,12), sticky="w")

        self.entry = ctk.CTkEntry(sb, placeholder_text="Search term…")
        self.entry.grid(row=2, column=0, padx=16, pady=(0,8), sticky="ew")
        self.entry.bind("<Return>", lambda e: self.start_search())

        _label(sb, "Domain filter (comma-separated):", muted=True).grid(row=3, column=0, padx=16, pady=(8,0), sticky="w")
        self.filter_var = ctk.StringVar()
        self.filter_entry = ctk.CTkEntry(sb, textvariable=self.filter_var, placeholder_text="youtube,twitch,gov")
        self.filter_entry.grid(row=4, column=0, padx=16, pady=(0,8), sticky="ew")

        _label(sb, "Sorting:", muted=True).grid(row=5, column=0, padx=16, pady=(8,0), sticky="w")
        self.sort_var = ctk.StringVar(value="No sorting")
        self.sort_dropdown = ctk.CTkOptionMenu(sb, variable=self.sort_var, values=["No sorting", "Domain", "Alphabetical"])
        self.sort_dropdown.grid(row=6, column=0, padx=16, pady=(0,12), sticky="ew")

        _btn_primary(sb, "🔍 Start search (TOR)", self.start_search).grid(row=7, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "🔗 Open link", self.open_selected_url).grid(row=8, column=0, padx=16, pady=(0,8), sticky="ew")
        _btn_subtle(sb, "🛈 Meta preview", self.show_title_preview).grid(row=9, column=0, padx=16, pady=(0,16), sticky="ew")

        # Main
        main = _card(self); main.grid(row=0, column=1, sticky="nsew", padx=(8,16), pady=16)
        main.grid_columnconfigure(0, weight=1); main.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(main, fg_color=BG_CARD); header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,6))
        header.grid_columnconfigure(0, weight=1)
        self.entry_header = ctk.CTkEntry(header, placeholder_text="Enter search term...", width=700)
        self.entry_header.grid(row=0, column=0, padx=6, pady=6, sticky="ew")
        self.entry_header.bind("<Return>", lambda e: self._sync_and_search())
        def sync_from_header(*_): self.entry.delete(0,'end'); self.entry.insert(0, self.entry_header.get())
        def sync_from_sidebar(*_): self.entry_header.delete(0,'end'); self.entry_header.insert(0, self.entry.get())
        self.entry_header.bind("<KeyRelease>", lambda e: sync_from_header())
        self.entry.bind("<KeyRelease>", lambda e: sync_from_sidebar())

        # Body split: results table (top) + details (bottom)
        body = ctk.CTkFrame(main, fg_color=BG_CARD)
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=0)

        # Table
        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass
        style.configure("Treeview", background=BG_CARD, foreground=FG_TEXT, fieldbackground=BG_CARD, rowheight=26, font=("Consolas",10))
        style.map('Treeview', background=[('selected','#23313A')])
        style.configure("Treeview.Heading", background=BG_CARD, foreground=ACCENT, font=("Consolas",11,"bold"))

        columns = ("#", "Title", "Domain")
        self.table = ttk.Treeview(body, columns=columns, show="headings", selectmode="browse")
        for col, w in zip(columns, (50, 720, 250)):
            self.table.heading(col, text=col)
            self.table.column(col, width=w, anchor="w")
        self.table.grid(row=0, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=vsb.set)
        vsb.grid(row=0, column=1, sticky="ns")
        self.table.bind("<<TreeviewSelect>>", self._on_select)

        # Details pane
        details = ctk.CTkFrame(body, fg_color=BG_CARD); details.grid(row=1, column=0, columnspan=2, sticky="ew", padx=0, pady=(8,0))
        details.grid_columnconfigure(0, weight=1); details.grid_rowconfigure(1, weight=0)

        self.url_var = ctk.StringVar(value="—")
        self.url_entry = ctk.CTkEntry(details, textvariable=self.url_var)
        self.url_entry.grid(row=0, column=0, padx=6, pady=(6,3), sticky="ew")

        self.snippet = ctk.CTkTextbox(details, height=100, wrap="word")
        self.snippet.grid(row=1, column=0, padx=6, pady=(0,6), sticky="ew")

        # Meta label
        self.title_preview_var = ctk.StringVar(value="Meta preview…")
        self.meta_label = _label(main, "", muted=True); self.meta_label.configure(textvariable=self.title_preview_var)
        self.meta_label.grid(row=2, column=0, padx=12, pady=(0,12), sticky="w")

        # Statusbar
        statusbar = _card(self); statusbar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0,16))
        statusbar.grid_columnconfigure(0, weight=1)
        _label(statusbar, "Tips: Press Enter to start search · Click a result to show details · Use the buttons on the right.", muted=True).grid(row=0, column=0, padx=12, pady=10, sticky="w")

        self.results = []
        self.selected_index = None

    # ===== behavior unchanged, only presentation updated =====
    def filter_and_sort(self, results):
        filt = getattr(self, "filter_var", ctk.StringVar(value="")).get().strip().lower()
        if filt:
            domains = [f.strip() for f in filt.split(",") if f.strip()]
            results = [r for r in results if any(d in r['domain'] for d in domains)]
        sort_mode = getattr(self, "sort_var", ctk.StringVar(value="No sorting")).get()
        if sort_mode == "Domain":
            results.sort(key=lambda x: x['domain'])
        elif sort_mode == "Alphabetical":
            results.sort(key=lambda x: x['title'].lower())
        return results

    def start_search(self):
        query = self.entry.get().strip() or self.entry_header.get().strip()
        if not query: return
        self.entry.delete(0,'end'); self.entry.insert(0, query)
        self.entry_header.delete(0,'end'); self.entry_header.insert(0, query)
        # Clear table and details
        for i in self.table.get_children():
            self.table.delete(i)
        self.url_var.set("—"); self.snippet.delete("1.0","end"); self.title_preview_var.set("Meta preview…")
        threading.Thread(target=self._search_thread, args=(query,), daemon=True).start()

    def _sync_and_search(self):
        self.start_search()

    def _search_thread(self, query):
        raw = search_duckduckgo_onion(query, 40)
        if not raw:
            return
        filtered = self.filter_and_sort(raw)
        self.results = filtered
        # Fill table
        for idx, item in enumerate(filtered, 1):
            self.table.insert("", "end", values=(idx, item['title'], item['domain']))

    def _on_select(self, _e):
        sel = self.table.selection()
        if not sel: return
        i = self.table.index(sel[0])
        if i < 0 or i >= len(self.results): return
        item = self.results[i]
        self.selected_index = i
        self.url_var.set(item['href'])
        self.snippet.delete("1.0","end"); self.snippet.insert("end", item['snippet'])

    def open_selected_url(self):
        if self.selected_index is None: return
        url = self.results[self.selected_index]['href']
        webbrowser.open(url)

    def show_title_preview(self):
        if self.selected_index is None: return
        url = self.results[self.selected_index]['href']
        self.title_preview_var.set("Loading meta info...")
        def fetch_title():
            title = get_site_title(url)
            self.title_preview_var.set(f"Meta preview: {title}")
        threading.Thread(target=fetch_title, daemon=True).start()

if __name__ == '__main__':
    _theme_setup()
    app = NullSearchApp()
    app.mainloop()
