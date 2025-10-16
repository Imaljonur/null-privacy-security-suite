#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Null_Social — Split social search in one window (PySide6 + QtWebEngine)
Layouts: 2×N (default), 1×N
Panes:
  • Nitter (Twitter) • Reddit (old) • YouTube (Invidious) • ChatGPT (web)
Features:
  • One query triggers all selected content panes (Nitter/Reddit/Invidious)
  • ChatGPT pane opens the ChatGPT web app (login required)
  • Instance/language selectors
  • Reddit cookie/consent auto-accept
Install:
  pip install PySide6
Run:
  python null_social.py
"""

from __future__ import annotations
import sys, math
from urllib.parse import quote_plus

from PySide6.QtCore import Qt, QUrl, QTimer
from PySide6.QtGui import QPalette, QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QGridLayout, QHBoxLayout, QVBoxLayout,
    QLineEdit, QPushButton, QCheckBox, QLabel, QComboBox, QGroupBox
)
from PySide6.QtWebEngineWidgets import QWebEngineView

# ---- Helpers ----

def make_dark_palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor(11, 15, 16))
    p.setColor(QPalette.WindowText, QColor(215, 224, 230))
    p.setColor(QPalette.Base, QColor(18, 23, 26))
    p.setColor(QPalette.AlternateBase, QColor(18, 23, 26))
    p.setColor(QPalette.ToolTipBase, QColor(18, 23, 26))
    p.setColor(QPalette.ToolTipText, QColor(215, 224, 230))
    p.setColor(QPalette.Text, QColor(215, 224, 230))
    p.setColor(QPalette.Button, QColor(18, 23, 26))
    p.setColor(QPalette.ButtonText, QColor(215, 224, 230))
    p.setColor(QPalette.BrightText, QColor(0, 255, 136))
    p.setColor(QPalette.Highlight, QColor(0, 255, 136))
    p.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
    return p

def build_nitter_url(base: str, q: str) -> str:
    base = base.rstrip('/')
    return f"{base}/search?f=tweets&q={quote_plus(q)}"

def build_reddit_url(base: str, q: str, sort: str = "new", time_param: str = "") -> str:
    base = base.rstrip('/')
    url = f"{base}/search?q={quote_plus(q)}&sort={quote_plus(sort)}"
    if time_param:
        url += f"&t={quote_plus(time_param)}"
    return url

def build_invidious_url(base: str, q: str) -> str:
    base = base.rstrip('/')
    return f"{base}/search?q={quote_plus(q)}"

# ---- Main Window ----

class NullSocialWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Null_Social — Nitter • Reddit • YouTube • ChatGPT")
        self.resize(1700, 1000)
        self._last_urls = {}
        self._init_ui()

    def _init_ui(self):
        central = QWidget(self)
        self.setCentralWidget(central)
        self.root = QVBoxLayout(central)
        self.root.setContentsMargins(8, 8, 8, 8)
        self.root.setSpacing(8)

        # Top controls
        top = QHBoxLayout()
        self.e_query = QLineEdit()
        self.e_query.setPlaceholderText("#news, ukraine, breaking")
        self.e_query.returnPressed.connect(self.do_search)

        self.chk_nitter = QCheckBox("Nitter"); self.chk_nitter.setChecked(True)
        self.chk_reddit = QCheckBox("Reddit"); self.chk_reddit.setChecked(True)
        self.chk_inv    = QCheckBox("YouTube"); self.chk_inv.setChecked(True)
        self.chk_gpt    = QCheckBox("ChatGPT"); self.chk_gpt.setChecked(True)

        # Layout switcher
        self.cmb_layout = QComboBox()
        self.cmb_layout.addItems(["2×N", "1×N"])
        self.cmb_layout.currentIndexChanged.connect(self.apply_layout)

        self.btn_search = QPushButton("Search")
        self.btn_search.clicked.connect(self.do_search)
        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self.do_clear)

        top.addWidget(self.e_query, 1)
        for w in (self.chk_nitter, self.chk_reddit, self.chk_inv, self.chk_gpt):
            top.addWidget(w)
        top.addWidget(QLabel("Layout:"))
        top.addWidget(self.cmb_layout)
        top.addWidget(self.btn_search)
        top.addWidget(self.btn_clear)
        self.root.addLayout(top)

        # Grid (dynamic)
        self.grid = QGridLayout()
        self.grid.setSpacing(8)
        self.root.addLayout(self.grid, 1)

        # --- Build panes ---
        # Nitter
        self.grp_nitter = QGroupBox("Nitter")
        v1 = QVBoxLayout(self.grp_nitter)
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("Instance:"))
        self.cmb_nitter = QComboBox()
        self.cmb_nitter.addItems([
            "https://nitter.poast.org",
            "https://nitter.net",
            "https://nitter.privacydev.net",
            "https://tweet.lambda.dance",
        ])
        self.cmb_nitter.setCurrentIndex(0)
        h1.addWidget(self.cmb_nitter, 1)
        v1.addLayout(h1)
        self.web_nitter = QWebEngineView()
        v1.addWidget(self.web_nitter, 1)

        # Reddit
        self.grp_reddit = QGroupBox("Reddit (old)")
        v2 = QVBoxLayout(self.grp_reddit)
        h2 = QHBoxLayout()
        h2.addWidget(QLabel("Instance:"))
        self.cmb_reddit = QComboBox()
        self.cmb_reddit.addItems(["https://old.reddit.com", "https://www.reddit.com"])
        self.cmb_reddit.setCurrentIndex(0)
        h2.addWidget(self.cmb_reddit)
        h2.addWidget(QLabel("Sort:"))
        self.cmb_sort = QComboBox()
        self.cmb_sort.addItems(["new", "relevance", "hot", "top", "comments"])
        self.cmb_sort.setCurrentIndex(0)
        h2.addWidget(self.cmb_sort)
        h2.addWidget(QLabel("Time:"))
        self.cmb_time = QComboBox()
        self.cmb_time.addItems(["", "hour", "day", "week", "month", "year", "all"])
        self.cmb_time.setCurrentIndex(0)
        h2.addWidget(self.cmb_time)
        v2.addLayout(h2)
        self.web_reddit = QWebEngineView()
        v2.addWidget(self.web_reddit, 1)

        # Invidious
        self.grp_inv = QGroupBox("YouTube (Invidious)")
        v3 = QVBoxLayout(self.grp_inv)
        h3 = QHBoxLayout()
        h3.addWidget(QLabel("Instance:"))
        self.cmb_inv = QComboBox()
        self.cmb_inv.addItems(["https://yewtu.be", "https://vid.puffyan.us", "https://invidious.snopyta.org"])
        self.cmb_inv.setCurrentIndex(0)
        h3.addWidget(self.cmb_inv, 1)
        v3.addLayout(h3)
        self.web_inv = QWebEngineView()
        v3.addWidget(self.web_inv, 1)

        # ChatGPT (web)
        self.grp_gpt = QGroupBox("ChatGPT (web)")
        v5 = QVBoxLayout(self.grp_gpt)
        h5 = QHBoxLayout()
        h5.addWidget(QLabel("Site:"))
        self.cmb_gpt = QComboBox()
        self.cmb_gpt.addItems(["https://chatgpt.com", "https://chat.openai.com"])
        self.cmb_gpt.setCurrentIndex(0)
        h5.addWidget(self.cmb_gpt, 1)
        self.btn_gpt = QPushButton("Open ChatGPT")
        self.btn_gpt.clicked.connect(self.open_chatgpt)
        h5.addWidget(self.btn_gpt)
        v5.addLayout(h5)
        self.web_gpt = QWebEngineView()
        v5.addWidget(self.web_gpt, 1)

        # Visibility toggles
        self.chk_nitter.stateChanged.connect(self.apply_layout)
        self.chk_reddit.stateChanged.connect(self.apply_layout)
        self.chk_inv.stateChanged.connect(self.apply_layout)
        self.chk_gpt.stateChanged.connect(self.apply_layout)

        # Reddit consent handling
        self.web_reddit.loadFinished.connect(lambda ok: self._reddit_auto_consent())
        self.web_reddit.urlChanged.connect(lambda u: self._reddit_auto_consent())

        # Initial layout
        self.apply_layout()

    # ---- Layout management ----

    def clear_grid(self):
        for i in reversed(range(self.grid.count())):
            item = self.grid.itemAt(i)
            w = item.widget()
            if w is not None:
                self.grid.removeWidget(w)

    def active_groups(self):
        groups = []
        if self.chk_nitter.isChecked(): groups.append(self.grp_nitter)
        if self.chk_reddit.isChecked(): groups.append(self.grp_reddit)
        if self.chk_inv.isChecked():    groups.append(self.grp_inv)
        if self.chk_gpt.isChecked():    groups.append(self.grp_gpt)
        return groups

    def apply_layout(self):
        mode = self.cmb_layout.currentText()
        self.clear_grid()
        groups = self.active_groups()
        n = len(groups)
        if n == 0:
            return
        # Reset stretches
        for c in range(max(4, n)):
            self.grid.setColumnStretch(c, 0)
        for r in range(max(2, math.ceil(n/2))):
            self.grid.setRowStretch(r, 0)

        if mode == "1×N":
            for c in range(n):
                self.grid.setColumnStretch(c, 1)
            self.grid.setRowStretch(0, 1)
            for idx, g in enumerate(groups):
                self.grid.addWidget(g, 0, idx)
        else:  # "2×N" → 2 columns, rows = ceil(n/2)
            for c in range(2):
                self.grid.setColumnStretch(c, 1)
            rows = math.ceil(n / 2)
            for r in range(rows):
                self.grid.setRowStretch(r, 1)
            r = c = 0
            for g in groups:
                self.grid.addWidget(g, r, c)
                c += 1
                if c >= 2:
                    c = 0
                    r += 1

    # ---- Actions ----

    def do_search(self):
        q = self.e_query.text().strip()
        if not q:
            return
        if self.chk_nitter.isChecked():
            url = build_nitter_url(self.cmb_nitter.currentText(), q)
            self._last_urls['nitter'] = url
            self.web_nitter.setUrl(QUrl(url))
        if self.chk_reddit.isChecked():
            url = build_reddit_url(self.cmb_reddit.currentText(), q, sort=self.cmb_sort.currentText(), time_param=self.cmb_time.currentText())
            self._last_urls['reddit'] = url
            self.web_reddit.setUrl(QUrl(url))
        if self.chk_inv.isChecked():
            url = build_invidious_url(self.cmb_inv.currentText(), q)
            self._last_urls['inv'] = url
            self.web_inv.setUrl(QUrl(url))
        # ChatGPT doesn't take query via URL; it's a chat. Leave as-is.

    def do_clear(self):
        dark_html = "<html><body style='background:#0B0F10;color:#8FA3AD;font-family:system-ui;padding:12px'>Cleared.</body></html>"
        if self.chk_nitter.isChecked(): self.web_nitter.setHtml(dark_html)
        if self.chk_reddit.isChecked(): self.web_reddit.setHtml(dark_html)
        if self.chk_inv.isChecked():    self.web_inv.setHtml(dark_html)
        if self.chk_gpt.isChecked():    self.web_gpt.setHtml(dark_html)

    def open_chatgpt(self):
        url = self.cmb_gpt.currentText().strip()
        if not url:
            url = "https://chatgpt.com"
        self.web_gpt.setUrl(QUrl(url))

    # ---- Reddit consent helper ----
    def _reddit_auto_consent(self):
        """Auto-accept Reddit consent and re-open intended search if needed."""
        try:
            cur = self.web_reddit.url().toString()
        except Exception:
            cur = ""
        js = r"""
        (function(){
          try {
            var clicked = false;
            try {
              var btns = Array.from(document.querySelectorAll('button, input[type="submit"], a[role="button"]'));
              var c = btns.filter(b => {
                var t = (b.innerText || b.value || '').toLowerCase();
                return /accept|agree|consent|ok|got it|i agree/.test(t);
              });
              if (c.length){ c[0].click(); clicked = true; }
            } catch(e){}
            try {
              var overlays = Array.from(document.querySelectorAll('[id*="overlay"],[class*="overlay"],[class*="consent"],[id*="consent"]'));
              overlays.forEach(el => { el.style.display='none'; el.remove && el.remove(); });
              var modals = Array.from(document.querySelectorAll('[role="dialog"],[class*="modal"]'));
              modals.forEach(m => { m.style.display='none'; m.remove && m.remove(); });
            } catch(e){}
            try { document.documentElement.style.overflow = 'auto'; document.body.style.overflow='auto'; } catch(e){}
            return clicked ? 'clicked' : 'no-btn';
          } catch(e){ return 'error'; }
        })();
        """
        try:
            self.web_reddit.page().runJavaScript(js)
        except Exception:
            pass
        if 'consent' in cur:
            target = self._last_urls.get('reddit', '')
            if target:
                QTimer.singleShot(1200, lambda: self.web_reddit.setUrl(QUrl(target)))

def main():
    app = QApplication(sys.argv)
    app.setPalette(make_dark_palette())
    win = NullSocialWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
