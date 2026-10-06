#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NEON//PING - cyberpunk ICMP latency monitor

Continuous ping to a target (default 1.1.1.1) with a live neon latency trace,
stat tiles, a hacker-style console and a 14-day history view.
Standard library only (tkinter + sqlite3).

Run:
    python neonping.py          (pythonw neonping.py hides the console window)

Engine:
    Windows  -> native ICMP API (iphlpapi.IcmpSendEcho): no admin, no subprocess
    other OS -> system `ping` binary, output parsed with a regex

History:
    every probe is appended to neonping_history.db (SQLite, WAL) next to this
    script by a background writer thread. Rows older than RETENTION_DAYS are
    pruned on start-up and once an hour. The HISTORY button (or the 1D..14D
    range buttons above the graph) switches the plot to an aggregated view:
    min-max band, average line and packet loss per time bucket.
"""

import ctypes
import math
import os
import queue
import random
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from collections import deque
from datetime import datetime, timedelta

TARGET_DEFAULT = "1.1.1.1"
INTERVAL_DEFAULT = 1.0        # seconds between probes
TIMEOUT_MS = 1000             # reply timeout per probe
MAX_POINTS = 300              # samples shown on the live trace
CONSOLE_MAX_LINES = 500
WARN_MS = 60                  # yellow above this
CRIT_MS = 150                 # red above this

RETENTION_DAYS = 14           # history kept on disk
HISTORY_RANGES = (1, 3, 5, 7, 11, 14)
HISTORY_REFRESH_MS = 20_000   # auto-refresh of the history view while shown
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "neonping_history.db")

IS_WIN = sys.platform.startswith("win")
ENGINE_HINT = "Windows ICMP API (iphlpapi.IcmpSendEcho)" if IS_WIN else "system ping binary"

BG          = "#04060b"
PANEL       = "#090d15"
PANEL2      = "#0d131d"
PLOT_BG     = "#05080e"
BORDER      = "#142634"
GRID        = "#0f2530"
GRID2       = "#1a3644"
CYAN        = "#00f0ff"
CYAN_MID    = "#00a7b5"
CYAN_DIM    = "#075560"
MAGENTA     = "#ff2bd6"
GREEN       = "#39ff14"
GREEN_DIM   = "#1c7a0c"
YELLOW      = "#ffe600"
RED         = "#ff2e4c"
TEXT        = "#c9f6ff"
MUTED       = "#4e6d7a"
WHITE       = "#e8fdff"


def blend(c1, c2, t):
    """Mix two #rrggbb colours; t=0 -> c1, t=1 -> c2."""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def nice_ceil(v):
    """Round a value up to a 'nice' axis maximum (10, 20, 25, 50, 100, ...)."""
    v = max(float(v), 10.0)
    mag = 10 ** math.floor(math.log10(v))
    for f in (1, 2, 2.5, 5, 10):
        if v <= f * mag:
            return f * mag
    return 10 * mag


def fmt_ms(v, prec=None):
    if v is None:
        return "--"
    if 0 <= v < 1:
        return "<1 ms"
    return f"{v:.{prec}f} ms" if prec is not None else f"{v:g} ms"


class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ulong),
        ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", _IP_OPTION_INFORMATION),
    ]


class WinIcmpPinger:
    """Native Windows ICMP echo via iphlpapi - works without admin rights."""

    NAME = "Windows ICMP API (iphlpapi.IcmpSendEcho)"
    STATUS = {
        11001: "BUFFER TOO SMALL", 11002: "NET UNREACHABLE", 11003: "HOST UNREACHABLE",
        11004: "PROTO UNREACHABLE", 11005: "PORT UNREACHABLE", 11006: "NO RESOURCES",
        11007: "BAD OPTION", 11008: "HW ERROR", 11009: "PACKET TOO BIG",
        11010: "TIMEOUT", 11011: "BAD REQUEST", 11012: "BAD ROUTE",
        11013: "TTL EXPIRED", 11014: "TTL EXPIRED (REASM)", 11015: "PARAM PROBLEM",
        11016: "SOURCE QUENCH", 11018: "BAD DESTINATION", 11050: "GENERAL FAILURE",
    }

    def __init__(self):
        from ctypes import wintypes
        self._dll = ctypes.WinDLL("iphlpapi", use_last_error=True)
        self._dll.IcmpCreateFile.restype = wintypes.HANDLE
        self._dll.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        self._dll.IcmpSendEcho.argtypes = [
            wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, wintypes.WORD,
            ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ]
        self._dll.IcmpSendEcho.restype = wintypes.DWORD
        handle = self._dll.IcmpCreateFile()
        if not handle or handle in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            raise OSError("IcmpCreateFile failed (err %d)" % ctypes.get_last_error())
        self._handle = handle
        payload = b"NEON//PING::" * 3
        self._payload = ctypes.create_string_buffer(payload, len(payload))
        self._payload_len = len(payload)
        self._reply_size = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(payload) + 8
        self._reply = ctypes.create_string_buffer(self._reply_size)

    def ping(self, ip, timeout_ms):
        addr = int.from_bytes(socket.inet_aton(ip), "little")
        n = self._dll.IcmpSendEcho(
            self._handle, addr,
            ctypes.cast(self._payload, ctypes.c_void_p), self._payload_len,
            None,
            ctypes.cast(self._reply, ctypes.c_void_p), self._reply_size,
            int(timeout_ms),
        )
        if n == 0:
            err = ctypes.get_last_error()
            return None, None, self.STATUS.get(err, "ERROR %d" % err)
        reply = _ICMP_ECHO_REPLY.from_buffer(self._reply)
        if reply.Status != 0:
            return None, None, self.STATUS.get(reply.Status, "STATUS %d" % reply.Status)
        return float(reply.RoundTripTime), int(reply.Options.Ttl), "OK"

    def close(self):
        if self._handle:
            self._dll.IcmpCloseHandle(self._handle)
            self._handle = None


class SubprocessPinger:
    """Fallback: shells out to the system `ping` binary and parses the reply."""

    NAME = "system ping binary"
    _RTT = re.compile(r"[=<]\s*([\d.,]+)\s*ms", re.I)
    _TTL = re.compile(r"ttl\s*[=:]\s*(\d+)", re.I)

    def ping(self, ip, timeout_ms):
        flags = 0
        if IS_WIN:
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip]
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        elif sys.platform == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(int(timeout_ms)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), ip]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout_ms / 1000 + 2, creationflags=flags)
        except subprocess.TimeoutExpired:
            return None, None, "TIMEOUT"
        except OSError as exc:
            return None, None, "ERROR %s" % exc
        out = (res.stdout or "") + (res.stderr or "")
        m = self._RTT.search(out)
        if not m:
            return None, None, "TIMEOUT"
        t = self._TTL.search(out)
        return float(m.group(1).replace(",", ".")), (int(t.group(1)) if t else None), "OK"

    def close(self):
        pass


def make_pinger():
    if IS_WIN:
        try:
            return WinIcmpPinger()
        except Exception:
            pass
    return SubprocessPinger()


class PingWorker(threading.Thread):
    """Background probe loop. Pushes ('sample', seq, rtt, ttl, status, ts) to a queue."""

    def __init__(self, target, interval, out_q, stop_evt):
        super().__init__(daemon=True, name="ping-worker")
        self.target = target
        self.interval = interval
        self.q = out_q
        self.stop_evt = stop_evt

    def run(self):
        try:
            ip = socket.gethostbyname(self.target)
        except (socket.gaierror, OSError) as exc:
            self.q.put(("fatal", f"DNS lookup failed for {self.target}: {exc}"))
            return
        try:
            pinger = make_pinger()
        except Exception as exc:
            self.q.put(("fatal", f"cannot initialise ping engine: {exc}"))
            return
        self.q.put(("info", f"engine online: {pinger.NAME} -> {ip}"))
        seq = 0
        try:
            while not self.stop_evt.is_set():
                t0 = time.monotonic()
                seq += 1
                try:
                    rtt, ttl, status = pinger.ping(ip, TIMEOUT_MS)
                except Exception as exc:
                    rtt, ttl, status = None, None, f"ERROR {exc}"
                self.q.put(("sample", seq, rtt, ttl, status, time.time()))
                remaining = self.interval - (time.monotonic() - t0)
                if remaining > 0:
                    self.stop_evt.wait(remaining)
        finally:
            pinger.close()


class HistoryStore:
    """SQLite ring buffer of the last RETENTION_DAYS of probes.

    One writer thread owns the write connection and batches inserts (commit every
    2 s or 50 rows). Readers open their own short-lived connections; WAL mode keeps
    readers and the writer from blocking each other.
    """

    SCHEMA = (
        "CREATE TABLE IF NOT EXISTS samples ("
        "  ts     REAL    NOT NULL,"      # unix time of the probe
        "  target TEXT    NOT NULL,"
        "  rtt    REAL,"                  # NULL = no reply
        "  ttl    INTEGER,"
        "  status TEXT"                   # NULL = OK, else reason
        ")"
    )

    def __init__(self, path, out_q):
        self.path = path
        self.out_q = out_q
        self._q = queue.Queue()
        self._thread = threading.Thread(target=self._run, name="history-writer", daemon=True)
        self._thread.start()

    def add(self, target, ts, rtt, ttl, status):
        self._q.put(("add", (ts, target, rtt, ttl, None if status == "OK" else status)))

    def close(self):
        self._q.put(("close", None))
        self._thread.join(timeout=5)

    def query_async(self, target, days, buckets, token):
        """Aggregate the last `days` into `buckets` equal time slots, off the GUI thread.
        Result arrives on out_q as ('history', payload)."""

        def work():
            t1 = time.time()
            t0 = t1 - days * 86400
            width = (t1 - t0) / buckets
            try:
                conn = sqlite3.connect(self.path)
                rows = conn.execute(
                    "SELECT CAST((ts - ?) / ? AS INTEGER) AS b,"
                    "       MIN(rtt), AVG(rtt), MAX(rtt), COUNT(*), SUM(rtt IS NULL)"
                    "  FROM samples"
                    " WHERE ts >= ? AND ts < ? AND target = ?"
                    " GROUP BY b ORDER BY b",
                    (t0, width, t0, t1, target),
                ).fetchall()
                total = conn.execute(
                    "SELECT COUNT(*), MIN(rtt), AVG(rtt), MAX(rtt), SUM(rtt IS NULL)"
                    "  FROM samples WHERE ts >= ? AND ts < ? AND target = ?",
                    (t0, t1, target),
                ).fetchone()
                conn.close()
            except sqlite3.Error as exc:
                self.out_q.put(("warn", f"history query failed: {exc}"))
                rows, total = [], (0, None, None, None, 0)
            self.out_q.put(("history", {
                "token": token, "target": target, "days": days, "t0": t0, "t1": t1,
                "buckets": buckets, "width": width, "rows": rows, "total": total,
            }))

        threading.Thread(target=work, name="history-query", daemon=True).start()

    @staticmethod
    def _prune(conn):
        cutoff = time.time() - RETENTION_DAYS * 86400
        cur = conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
        conn.commit()
        if cur.rowcount:
            conn.execute("PRAGMA incremental_vacuum")
        return cur.rowcount

    def _run(self):
        try:
            conn = sqlite3.connect(self.path)
            conn.execute("PRAGMA auto_vacuum=INCREMENTAL")      # only effective on a new file
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(self.SCHEMA)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts)")
            conn.commit()
            pruned = self._prune(conn)
            count, oldest = conn.execute("SELECT COUNT(*), MIN(ts) FROM samples").fetchone()
            size_mb = os.path.getsize(self.path) / 1e6
            oldest_s = datetime.fromtimestamp(oldest).strftime("%Y-%m-%d %H:%M") if oldest else "-"
            self.out_q.put(("info",
                            f"history store: {os.path.basename(self.path)}  |  {count:,} probes  |  "
                            f"oldest {oldest_s}  |  {size_mb:.1f} MB  |  pruned {pruned}  |  "
                            f"retention {RETENTION_DAYS} d"))
        except Exception as exc:
            self.out_q.put(("warn", f"history store disabled: {exc}"))
            while True:                                   # keep draining so add() never blocks
                kind, _ = self._q.get()
                if kind == "close":
                    return

        pending = []
        last_commit = last_prune = time.monotonic()
        try:
            while True:
                try:
                    kind, row = self._q.get(timeout=1.0)
                except queue.Empty:
                    kind, row = None, None
                if kind == "add":
                    pending.append(row)
                now = time.monotonic()
                if pending and (kind == "close" or len(pending) >= 50 or now - last_commit >= 2.0):
                    conn.executemany("INSERT INTO samples VALUES (?, ?, ?, ?, ?)", pending)
                    conn.commit()
                    pending.clear()
                    last_commit = now
                if kind == "close":
                    break
                if now - last_prune >= 3600:
                    self._prune(conn)
                    last_prune = now
        finally:
            conn.close()


class NeonPing(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NEON//PING :: ICMP latency monitor")
        self.configure(bg=BG)
        self.ui = self.winfo_fpixels("1i") / 96.0           # DPI scale factor
        self.geometry(f"{int(1100 * self.ui)}x{int(740 * self.ui)}")
        self.minsize(int(900 * self.ui), int(600 * self.ui))

        self.mono = self._pick_font((
            "Cascadia Mono", "Cascadia Code", "Consolas", "JetBrains Mono",
            "Fira Code", "DejaVu Sans Mono", "Lucida Console", "Courier New",
        ))

        def font(size, weight="normal"):
            return tkfont.Font(family=self.mono, size=size, weight=weight)

        self.f_title = font(20, "bold")
        self.f_sub = font(9)
        self.f_ui = font(10)
        self.f_ui_b = font(10, "bold")
        self.f_small = font(8)
        self.f_small_b = font(8, "bold")
        self.f_stat_val = font(16, "bold")

        self.samples = deque(maxlen=MAX_POINTS)   # (seq, rtt|None, ts)
        self.q = queue.Queue()
        self.worker = None
        self.stop_evt = None
        self.running = False
        self.run_since = None
        self.run_accum = 0.0
        self.head_xy = None
        self.pulse = 0.0
        self.blink = False
        self.mode = "live"                        # "live" | "history"
        self.hist_days = HISTORY_RANGES[0]
        self.hist_data = None
        self.hist_token = 0
        self.hist_pending = False
        self._reset_counters()

        self.store = HistoryStore(DB_PATH, self.q)

        self._build_ui()
        self._boot_banner()
        self.after(100, self._poll_queue)
        self.after(500, self._tick_clock)
        self.after(50, self._tick_pulse)
        self.after(3000, self._glitch_title)
        self.after(HISTORY_REFRESH_MS, self._tick_history)
        self.bind("<space>", self._on_space)
        self.bind("<Key-h>", self._on_hotkey_h)
        self.bind("<Key-H>", self._on_hotkey_h)
        self.bind("<Escape>", lambda e: self.on_close())
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _reset_counters(self):
        self.sent = 0
        self.received = 0
        self.rtt_min = None
        self.rtt_max = None
        self.rtt_sum = 0.0
        self.last_rtt = None
        self.jitter_sum = 0.0
        self.jitter_n = 0

    @staticmethod
    def _pick_font(prefs):
        fams = set(tkfont.families())
        for f in prefs:
            if f in fams:
                return f
        return "Courier"

    def _current_target(self):
        if self.worker and self.running:
            return self.worker.target
        return self.target_var.get().strip() or TARGET_DEFAULT

    def _build_ui(self):
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=16, pady=(12, 4))
        self.title_lbl = tk.Label(hdr, text="NEON//PING", font=self.f_title, fg=CYAN, bg=BG)
        self.title_lbl.pack(side="left")
        tk.Label(hdr, text="▌ ICMP LATENCY MONITOR", font=self.f_sub, fg=MAGENTA, bg=BG
                 ).pack(side="left", padx=(12, 0), pady=(8, 0))
        self.clock_lbl = tk.Label(hdr, text="", font=self.f_ui, fg=MUTED, bg=BG)
        self.clock_lbl.pack(side="right")
        self.live_lbl = tk.Label(hdr, text="● IDLE", font=self.f_ui_b, fg=MUTED, bg=BG)
        self.live_lbl.pack(side="right", padx=(0, 18))

        tk.Frame(self, height=1, bg=CYAN_DIM).pack(fill="x", padx=16)

        ctl = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        ctl.pack(fill="x", padx=16, pady=(8, 6))
        tk.Label(ctl, text="TARGET", font=self.f_small, fg=MUTED, bg=PANEL
                 ).pack(side="left", padx=(12, 6), pady=10)
        self.target_var = tk.StringVar(value=TARGET_DEFAULT)
        self.target_entry = tk.Entry(
            ctl, textvariable=self.target_var, width=22, font=self.f_ui, fg=GREEN, bg=PANEL2,
            insertbackground=GREEN, relief="flat", highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=CYAN,
            disabledbackground=PANEL2, disabledforeground=CYAN_MID,
        )
        self.target_entry.pack(side="left", ipady=4)
        self.target_entry.bind("<Return>", lambda e: self.start())

        tk.Label(ctl, text="INTERVAL", font=self.f_small, fg=MUTED, bg=PANEL
                 ).pack(side="left", padx=(18, 6))
        self.interval_var = tk.StringVar(value=f"{INTERVAL_DEFAULT:.1f}")
        self.interval_box = tk.Spinbox(
            ctl, textvariable=self.interval_var, from_=0.2, to=10.0, increment=0.1,
            format="%.1f", width=5, font=self.f_ui, fg=GREEN, bg=PANEL2,
            buttonbackground=PANEL2, insertbackground=GREEN, relief="flat",
            highlightthickness=1, highlightbackground=BORDER, highlightcolor=CYAN,
            disabledbackground=PANEL2, disabledforeground=CYAN_MID,
        )
        self.interval_box.pack(side="left", ipady=3)
        tk.Label(ctl, text="s", font=self.f_small, fg=MUTED, bg=PANEL).pack(side="left", padx=(4, 0))

        self.start_btn = self._neon_button(ctl, "▶  START", CYAN, self.toggle)
        self.start_btn.wrap.pack(side="right", padx=(6, 12), pady=8)
        self.clear_btn = self._neon_button(ctl, "CLEAR", MAGENTA, self.clear)
        self.clear_btn.wrap.pack(side="right", padx=6, pady=8)
        self.hist_btn = self._neon_button(ctl, "◷  HISTORY", YELLOW, self.toggle_mode)
        self.hist_btn.wrap.pack(side="right", padx=6, pady=8)

        stats = tk.Frame(self, bg=BG)
        stats.pack(fill="x", padx=16, pady=(0, 6))
        self.stat_lbls = {}
        tiles = (
            ("cur", "CURRENT", CYAN), ("min", "MIN", GREEN), ("avg", "AVG", MAGENTA),
            ("max", "MAX", YELLOW), ("jit", "JITTER", CYAN), ("loss", "LOSS", RED),
            ("pkts", "SENT / RECV", TEXT), ("up", "UPTIME", TEXT),
        )
        for col, (key, label, color) in enumerate(tiles):
            stats.columnconfigure(col, weight=1, uniform="tile")
            tile = tk.Frame(stats, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
            tile.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 4, 0))
            tk.Label(tile, text=label, font=self.f_small, fg=MUTED, bg=PANEL
                     ).pack(anchor="w", padx=10, pady=(6, 0))
            val = tk.Label(tile, text="--", font=self.f_stat_val, fg=color, bg=PANEL)
            val.pack(anchor="w", padx=10, pady=(0, 6))
            self.stat_lbls[key] = val

        gframe = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        gframe.pack(fill="both", expand=True, padx=16, pady=(0, 6))
        gtop = tk.Frame(gframe, bg=PANEL)
        gtop.pack(fill="x")
        self.graph_title = tk.Label(gtop, text="▌ LATENCY TRACE", font=self.f_small,
                                    fg=CYAN_MID, bg=PANEL)
        self.graph_title.pack(side="left", padx=10, pady=(6, 2))

        rbar = tk.Frame(gtop, bg=PANEL)
        rbar.pack(side="right", padx=(0, 8))
        tk.Label(rbar, text="RANGE", font=self.f_small, fg=MUTED, bg=PANEL).pack(side="left", padx=(0, 6))
        self.range_btns = {}
        for days in (0,) + HISTORY_RANGES:
            btn = tk.Button(
                rbar, text="LIVE" if days == 0 else f"{days}D", font=self.f_small_b,
                fg=MUTED, bg=PANEL, activeforeground=CYAN, activebackground=PANEL2,
                relief="flat", bd=0, padx=7, pady=1, highlightthickness=0, cursor="hand2",
                command=lambda d=days: self.set_range(d),
            )
            btn.pack(side="left", padx=1)
            self.range_btns[days] = btn
        self.graph_info = tk.Label(gtop, text=f"window 0/{MAX_POINTS}", font=self.f_small,
                                   fg=MUTED, bg=PANEL)
        self.graph_info.pack(side="right", padx=10)
        self._refresh_range_buttons()

        self.canvas = tk.Canvas(gframe, bg=PLOT_BG, highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True, padx=1, pady=(0, 1))
        self.canvas.bind("<Configure>", lambda e: self.redraw())

        cframe = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        cframe.pack(fill="x", padx=16, pady=(0, 6))
        tk.Label(cframe, text="▌ CONSOLE", font=self.f_small, fg=CYAN_MID, bg=PANEL
                 ).pack(anchor="w", padx=10, pady=(6, 2))
        self.console = tk.Text(
            cframe, height=7, font=self.f_small, fg=TEXT, bg="#030508", relief="flat", bd=0,
            wrap="none", state="disabled", cursor="arrow", padx=10, pady=4,
            selectbackground=CYAN_DIM, selectforeground=WHITE,
        )
        self.console.pack(fill="x", padx=1, pady=(0, 1))
        for tag, color in (("ok", GREEN), ("warn", YELLOW), ("err", RED),
                           ("sys", CYAN), ("mag", MAGENTA), ("dim", MUTED)):
            self.console.tag_configure(tag, foreground=color)

        self.status_lbl = tk.Label(
            self, anchor="w", font=self.f_small, fg=MUTED, bg=BG,
            text=f"engine: {ENGINE_HINT}   |   timeout {TIMEOUT_MS} ms   |   "
                 f"history {RETENTION_DAYS} d in {os.path.basename(DB_PATH)}   |   "
                 f"SPACE start/stop   |   H history   |   ESC quit",
        )
        self.status_lbl.pack(fill="x", padx=16, pady=(0, 8))

    def _neon_button(self, parent, text, color, command):
        wrap = tk.Frame(parent, bg=color, padx=1, pady=1)       # 1 px neon border
        btn = tk.Button(
            wrap, text=text, command=command, font=self.f_ui_b, fg=color, bg=PANEL2,
            activeforeground=BG, activebackground=color, relief="flat", bd=0,
            padx=14, pady=5, highlightthickness=0, cursor="hand2",
        )
        btn.pack()
        btn.wrap = wrap
        btn.neon = color
        btn.bind("<Enter>", lambda e: btn.configure(bg=blend(PANEL2, btn.neon, 0.22)))
        btn.bind("<Leave>", lambda e: btn.configure(bg=PANEL2))
        return btn

    @staticmethod
    def _style_button(btn, text, color):
        btn.neon = color
        btn.configure(text=text, fg=color, activebackground=color, bg=PANEL2)
        btn.wrap.configure(bg=color)

    def _refresh_range_buttons(self):
        active = 0 if self.mode == "live" else self.hist_days
        for days, btn in self.range_btns.items():
            if days == active:
                btn.configure(fg=BG, bg=GREEN if days == 0 else YELLOW)
            else:
                btn.configure(fg=MUTED, bg=PANEL)

    def log(self, msg, tag="dim"):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.console.configure(state="normal")
        self.console.insert("end", f"[{stamp}] ", "dim")
        self.console.insert("end", msg + "\n", tag)
        last = int(self.console.index("end-1c").split(".")[0])
        if last > CONSOLE_MAX_LINES:
            self.console.delete("1.0", f"{last - CONSOLE_MAX_LINES + 1}.0")
        self.console.see("end")
        self.console.configure(state="disabled")

    def _boot_banner(self):
        lines = [
            ("NEON//PING v1.1 online - cyberpunk ICMP monitor", "mag"),
            (f"engine: {ENGINE_HINT}", "sys"),
            (f"target locked: {TARGET_DEFAULT}   (timeout {TIMEOUT_MS} ms, "
             f"live trace {MAX_POINTS} samples)", "sys"),
            ("press ▶ START or SPACE to begin the trace, ◷ HISTORY or H for the "
             f"{RETENTION_DAYS}-day archive", "dim"),
        ]

        def emit(i=0):
            if i < len(lines):
                self.log(*lines[i])
                self.after(160, emit, i + 1)

        emit()

    def toggle(self):
        if self.running:
            self.stop()
        else:
            self.start()

    def start(self):
        if self.running:
            return
        target = self.target_var.get().strip()
        if not target:
            self.log("no target specified", "err")
            return
        try:
            interval = max(0.1, float(self.interval_var.get().replace(",", ".")))
        except ValueError:
            interval = INTERVAL_DEFAULT
            self.interval_var.set(f"{interval:.1f}")
        self.stop_evt = threading.Event()
        self.worker = PingWorker(target, interval, self.q, self.stop_evt)
        self.worker.start()
        self.running = True
        self.run_since = time.monotonic()
        self.target_entry.configure(state="disabled")
        self.interval_box.configure(state="disabled")
        self._style_button(self.start_btn, "■  STOP", RED)
        self.live_lbl.configure(text="● LIVE", fg=GREEN)
        self.log(f"trace started -> {target} every {interval:g} s", "sys")
        self.focus_set()

    def stop(self):
        if not self.running:
            return
        if self.stop_evt:
            self.stop_evt.set()
        self.running = False
        if self.run_since is not None:
            self.run_accum += time.monotonic() - self.run_since
            self.run_since = None
        self.target_entry.configure(state="normal")
        self.interval_box.configure(state="normal")
        self._style_button(self.start_btn, "▶  START", CYAN)
        self.live_lbl.configure(text="● IDLE", fg=MUTED)
        self.log("trace stopped", "warn")

    def clear(self):
        self.samples.clear()
        self._reset_counters()
        self.run_accum = 0.0
        if self.running:
            self.run_since = time.monotonic()
        self.head_xy = None
        self.redraw()
        self._update_stats()
        self.log("live buffers purged (history on disk untouched)", "warn")

    def toggle_mode(self):
        self.set_mode("live" if self.mode == "history" else "history")

    def set_range(self, days):
        if days == 0:
            self.set_mode("live")
        else:
            self.hist_days = days
            self.set_mode("history", refresh=True)

    def set_mode(self, mode, refresh=False):
        changed = mode != self.mode
        self.mode = mode
        if mode == "history":
            self._style_button(self.hist_btn, "◉  LIVE VIEW", GREEN)
            unit = "DAY" if self.hist_days == 1 else "DAYS"
            self.graph_title.configure(text=f"▌ HISTORY  |  LAST {self.hist_days} {unit}")
            if changed or refresh:
                self.hist_data = None
                self._request_history(force=True)
        else:
            self._style_button(self.hist_btn, "◷  HISTORY", YELLOW)
            self.graph_title.configure(text="▌ LATENCY TRACE")
            self.graph_info.configure(text=f"window {len(self.samples)}/{MAX_POINTS}")
        self._refresh_range_buttons()
        self.redraw()

    def _on_space(self, event):
        if isinstance(event.widget, (tk.Entry, tk.Spinbox, tk.Button)):
            return None
        self.toggle()
        return "break"

    def _on_hotkey_h(self, event):
        if isinstance(event.widget, (tk.Entry, tk.Spinbox)):
            return None
        self.toggle_mode()
        return "break"

    def on_close(self):
        if self.stop_evt:
            self.stop_evt.set()
        self.store.close()
        self.destroy()

    def _poll_queue(self):
        dirty = False
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "sample":
                    self._on_sample(*msg[1:])
                    dirty = True
                elif kind == "history":
                    self._on_history(msg[1])
                elif kind == "info":
                    self.log(msg[1], "sys")
                elif kind == "warn":
                    self.log(msg[1], "warn")
                elif kind == "fatal":
                    self.log(msg[1], "err")
                    self.stop()
        except queue.Empty:
            pass
        if dirty:
            if self.mode == "live":
                self.redraw()
            self._update_stats()
        self.after(100, self._poll_queue)

    def _on_sample(self, seq, rtt, ttl, status, ts):
        self.sent += 1
        self.samples.append((seq, rtt, ts))
        target = self.worker.target if self.worker else "?"
        self.store.add(target, ts, rtt, ttl, status)
        if rtt is None:
            self.log(f"seq={seq}  ✖ {status}  - no reply from {target}", "err")
            return
        self.received += 1
        self.rtt_sum += rtt
        self.rtt_min = rtt if self.rtt_min is None else min(self.rtt_min, rtt)
        self.rtt_max = rtt if self.rtt_max is None else max(self.rtt_max, rtt)
        if self.last_rtt is not None:
            self.jitter_sum += abs(rtt - self.last_rtt)
            self.jitter_n += 1
        self.last_rtt = rtt
        tag = "ok" if rtt < WARN_MS else ("warn" if rtt < CRIT_MS else "err")
        ttl_s = ttl if ttl is not None else "?"
        self.log(f"reply from {target}: seq={seq} ttl={ttl_s} time={fmt_ms(rtt)}", tag)

    def _request_history(self, force=False):
        if self.hist_pending and not force:
            return                                       # periodic refresh must not pile up
        pw = max(200.0, self.canvas.winfo_width() - 84 * self.ui)
        buckets = int(max(120, min(900, pw / 2)))          # ~2 px per bucket
        self.hist_token += 1
        self.hist_pending = True
        self.store.query_async(self._current_target(), self.hist_days, buckets, self.hist_token)

    def _on_history(self, payload):
        if payload["token"] != self.hist_token:
            return
        self.hist_pending = False
        self.hist_data = payload
        if self.mode == "history":
            stamp = datetime.now().strftime("%H:%M:%S")
            self.graph_info.configure(
                text=f"updated {stamp}  |  bucket {payload['width'] / 60:.1f} min  |  "
                     f"{len(payload['rows'])}/{payload['buckets']} buckets")
            self.redraw()

    def _tick_history(self):
        if self.mode == "history" and not self.hist_pending:
            self._request_history()
        self.after(HISTORY_REFRESH_MS, self._tick_history)

    def _stat(self, key, text, color=None):
        if color:
            self.stat_lbls[key].configure(text=text, fg=color)
        else:
            self.stat_lbls[key].configure(text=text)

    @staticmethod
    def _level_color(v):
        if v is None:
            return MUTED
        if v < WARN_MS:
            return CYAN
        if v < CRIT_MS:
            return YELLOW
        return RED

    def _update_stats(self):
        cur = self.samples[-1][1] if self.samples else None
        if self.samples and cur is None:
            self._stat("cur", "LOST", RED)
        else:
            self._stat("cur", fmt_ms(cur), self._level_color(cur))
        self._stat("min", fmt_ms(self.rtt_min))
        avg = self.rtt_sum / self.received if self.received else None
        self._stat("avg", fmt_ms(avg, 1))
        self._stat("max", fmt_ms(self.rtt_max))
        jit = self.jitter_sum / self.jitter_n if self.jitter_n else None
        self._stat("jit", fmt_ms(jit, 1))
        if self.sent:
            loss = 100.0 * (self.sent - self.received) / self.sent
            self._stat("loss", f"{loss:.1f} %", RED if loss > 0 else GREEN)
        else:
            self._stat("loss", "--")
        self._stat("pkts", f"{self.sent} / {self.received}")
        if self.mode == "live":
            self.graph_info.configure(text=f"window {len(self.samples)}/{MAX_POINTS}")

    def _tick_clock(self):
        self.clock_lbl.configure(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        up = self.run_accum + ((time.monotonic() - self.run_since) if self.run_since else 0.0)
        hh, rem = divmod(int(up), 3600)
        mm, ss = divmod(rem, 60)
        self._stat("up", f"{hh:02d}:{mm:02d}:{ss:02d}")
        if self.running:
            self.blink = not self.blink
            self.live_lbl.configure(fg=GREEN if self.blink else GREEN_DIM)
        self.after(500, self._tick_clock)

    def _tick_pulse(self):
        self.pulse = (self.pulse + 0.28) % (2 * math.pi)
        if self.head_xy is not None and self.running and self.mode == "live":
            hx, hy = self.head_xy
            r = (5 + 5 * (1 + math.sin(self.pulse)) / 2) * self.ui
            self.canvas.coords("headring", hx - r, hy - r, hx + r, hy + r)
        self.after(50, self._tick_pulse)

    def _glitch_title(self):
        if random.random() < 0.75:
            base = "NEON//PING"
            pool = "#%&$@01<>\\|"
            glitched = "".join(ch if random.random() > 0.35 else random.choice(pool) for ch in base)
            self.title_lbl.configure(text=glitched, fg=MAGENTA)
            self.after(70, lambda: self.title_lbl.configure(text=base, fg=CYAN))
        self.after(random.randint(2500, 6500), self._glitch_title)

    def redraw(self):
        c = self.canvas
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 80 or h < 60:
            return
        if self.mode == "history":
            self._draw_history(c, w, h)
        else:
            self._draw_live(c, w, h)

    def _plot_rect(self, w, h):
        ui = self.ui
        return 62 * ui, 26 * ui, w - 22 * ui, h - 30 * ui

    def _draw_y_axis(self, c, x0, y0, x1, y1, ymax, divs=5):
        ui, ph = self.ui, y1 - y0
        for i in range(divs + 1):
            yy = y1 - ph * i / divs
            c.create_line(x0, yy, x1, yy, fill=GRID, dash=(2, 4))
            c.create_text(x0 - 8 * ui, yy, text=f"{ymax * i / divs:g}", anchor="e",
                          fill=MUTED, font=self.f_small)
        c.create_text(x0 - 8 * ui, y0 - 12 * ui, text="ms", anchor="e", fill=CYAN_DIM, font=self.f_small)

    def _draw_thresholds(self, c, x0, x1, ymax, Y):
        if ymax > WARN_MS:
            c.create_line(x0, Y(WARN_MS), x1, Y(WARN_MS), fill=blend(PLOT_BG, YELLOW, 0.35), dash=(6, 6))
        if ymax > CRIT_MS:
            c.create_line(x0, Y(CRIT_MS), x1, Y(CRIT_MS), fill=blend(PLOT_BG, RED, 0.40), dash=(6, 6))

    def _draw_overlay(self, c, x0, y0, x1, y1):
        """CRT scanlines + corner brackets, drawn last."""
        yy = int(y0) + 1
        while yy < y1:
            c.create_rectangle(x0 + 1, yy, x1 - 1, yy + 1, fill="#000000", stipple="gray50", outline="")
            yy += 3
        s = 12 * self.ui
        for cx, cy, dx, dy in ((x0, y0, 1, 1), (x1, y0, -1, 1), (x0, y1, 1, -1), (x1, y1, -1, -1)):
            c.create_line(cx, cy + dy * s, cx, cy, cx + dx * s, cy, fill=CYAN, width=2)

    def _glow_line(self, c, flat, color=CYAN, base=10):
        ui = self.ui
        c.create_line(flat, fill=blend(PLOT_BG, color, 0.18), width=base * ui,
                      capstyle="round", joinstyle="round")
        c.create_line(flat, fill=blend(PLOT_BG, color, 0.45), width=base * ui / 2,
                      capstyle="round", joinstyle="round")
        c.create_line(flat, fill=color, width=2 * ui, capstyle="round", joinstyle="round")

    def _draw_live(self, c, w, h):
        ui = self.ui
        x0, y0, x1, y1 = self._plot_rect(w, h)
        pw, ph = x1 - x0, y1 - y0

        samples = list(self.samples)
        rtts = [s[1] for s in samples if s[1] is not None]
        ymax = nice_ceil((max(rtts) * 1.25) if rtts else 50)
        n = MAX_POINTS
        m = len(samples)
        step = pw / (n - 1)

        def X(k):                       # newest sample sits at the right edge
            return x1 - (m - 1 - k) * step

        def Y(v):
            return y1 - (v / ymax) * ph

        c.create_rectangle(x0, y0, x1, y1, fill=PLOT_BG, outline=GRID2)
        self._draw_y_axis(c, x0, y0, x1, y1, ymax)

        for i in range(0, n, 25):
            xx = x1 - i * step
            c.create_line(xx, y0, xx, y1, fill=GRID, dash=(2, 4))
            k = m - 1 - i
            if i % 50 == 0 and k >= 0:
                stamp = datetime.fromtimestamp(samples[k][2]).strftime("%H:%M:%S")
                c.create_text(xx, y1 + 6 * ui, text=stamp, anchor="n", fill=MUTED, font=self.f_small)

        self._draw_thresholds(c, x0, x1, ymax, Y)

        # lost probes: red glitch bands across the full height
        for k, (_seq, rtt, _ts) in enumerate(samples):
            if rtt is None:
                xx = X(k)
                c.create_rectangle(xx - step / 2, y0 + 1, xx + step / 2, y1 - 1,
                                   fill=RED, stipple="gray25", outline="")
                c.create_line(xx, y0 + 1, xx, y0 + 8 * ui, fill=RED, width=2)

        # contiguous runs of successful replies, broken at every lost probe
        segs, cur = [], []
        for k, (_seq, rtt, _ts) in enumerate(samples):
            if rtt is None:
                if cur:
                    segs.append(cur)
                    cur = []
            else:
                cur.append((X(k), Y(rtt)))
        if cur:
            segs.append(cur)

        for seg in segs:
            if len(seg) >= 2:
                flat = [v for p in seg for v in p]
                poly = [seg[0][0], y1] + flat + [seg[-1][0], y1]
                c.create_polygon(poly, fill=CYAN_DIM, stipple="gray25", outline="")   # dithered fill
                self._glow_line(c, flat)
            else:
                px, py = seg[0]
                r = 2 * ui
                c.create_oval(px - r, py - r, px + r, py + r, fill=CYAN, outline="")

        if self.received:
            avg = self.rtt_sum / self.received
            if avg <= ymax:
                ya = Y(avg)
                c.create_line(x0, ya, x1, ya, fill=MAGENTA, dash=(4, 4))
                c.create_text(x0 + 6 * ui, ya - 2, text=f"avg {avg:.1f}", anchor="sw",
                              fill=MAGENTA, font=self.f_small)

        # head marker on the newest sample (the ring is animated by _tick_pulse)
        self.head_xy = None
        if samples and samples[-1][1] is not None:
            hx, hy = X(m - 1), Y(samples[-1][1])
            self.head_xy = (hx, hy)
            c.create_line(hx, y0, hx, y1, fill=CYAN_DIM, dash=(1, 3))
            r = 5 * ui
            c.create_oval(hx - r, hy - r, hx + r, hy + r, outline=CYAN, width=1, tags="headring")
            r = 3 * ui
            c.create_oval(hx - r, hy - r, hx + r, hy + r, fill=WHITE, outline=CYAN)
            ly = hy - 14 * ui if hy - 14 * ui > y0 + 10 * ui else hy + 14 * ui
            c.create_text(hx - 8 * ui, ly, text=fmt_ms(samples[-1][1]), anchor="e",
                          fill=WHITE, font=self.f_ui_b)
        elif samples:
            c.create_text(X(m - 1) - 8 * ui, y0 + 16 * ui, text="✖ LOST", anchor="e",
                          fill=RED, font=self.f_ui_b)

        self._draw_overlay(c, x0, y0, x1, y1)
        c.create_text(x0 + 10 * ui, y0 + 8 * ui, text=f"LATENCY // {self._current_target()}",
                      anchor="nw", fill=CYAN_MID, font=self.f_small)
        c.create_text(x1 - 10 * ui, y0 + 8 * ui, text=f"{m}/{n} samples", anchor="ne",
                      fill=MUTED, font=self.f_small)

    @staticmethod
    def _time_ticks(t0, t1, days):
        """(timestamp, label) pairs for the x axis, aligned to local clock boundaries."""
        if days <= 1:
            step, fmt = 3 * 3600, "%H:%M"
        elif days <= 3:
            step, fmt = 12 * 3600, "%m-%d %H:%M"
        elif days <= 7:
            step, fmt = 24 * 3600, "%m-%d"
        else:
            step, fmt = 2 * 24 * 3600, "%m-%d"
        start = datetime.fromtimestamp(t0)
        if step >= 86400:
            t = start.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            hours = step // 3600
            t = start.replace(hour=start.hour - start.hour % hours, minute=0, second=0, microsecond=0)
        ticks = []
        while t.timestamp() <= t1:
            if t.timestamp() >= t0:
                ticks.append((t.timestamp(), t.strftime(fmt)))
            t += timedelta(seconds=step)
        return ticks

    def _draw_history(self, c, w, h):
        ui = self.ui
        x0, y0, x1, y1 = self._plot_rect(w, h)
        pw, ph = x1 - x0, y1 - y0
        c.create_rectangle(x0, y0, x1, y1, fill=PLOT_BG, outline=GRID2)

        data = self.hist_data
        if data is None or data["days"] != self.hist_days:
            self._draw_overlay(c, x0, y0, x1, y1)
            c.create_text((x0 + x1) / 2, (y0 + y1) / 2, text="▸ QUERYING HISTORY ...",
                          fill=CYAN_MID, font=self.f_ui_b)
            return

        rows, t0, t1, width = data["rows"], data["t0"], data["t1"], data["width"]
        days, target = data["days"], data["target"]
        span = t1 - t0

        def X(t):
            return x0 + (t - t0) / span * pw

        # y scale on the 97th percentile of bucket maxima so one spike cannot flatten the plot
        maxs = sorted(r[3] for r in rows if r[3] is not None)
        if maxs:
            p97 = maxs[min(len(maxs) - 1, int(len(maxs) * 0.97))]
            ymax = nice_ceil(p97 * 1.2)
        else:
            ymax = 50.0

        def Y(v):
            return y1 - (min(v, ymax) / ymax) * ph

        self._draw_y_axis(c, x0, y0, x1, y1, ymax)
        for t, label in self._time_ticks(t0, t1, days):
            xx = X(t)
            c.create_line(xx, y0, xx, y1, fill=GRID, dash=(2, 4))
            c.create_text(xx, y1 + 6 * ui, text=label, anchor="n", fill=MUTED, font=self.f_small)
        self._draw_thresholds(c, x0, x1, ymax, Y)

        if not rows:
            c.create_text((x0 + x1) / 2, (y0 + y1) / 2,
                          text=f"NO DATA FOR {target} IN THE LAST {days} DAY(S)",
                          fill=MUTED, font=self.f_ui_b)
        else:
            # packet loss: red bars hanging from the top, height = lost share of the bucket
            for b, _mn, _av, _mx, cnt, lost in rows:
                if lost:
                    bx0, bx1 = X(t0 + b * width), X(t0 + (b + 1) * width)
                    c.create_rectangle(bx0, y0 + 1, max(bx1, bx0 + 1), y0 + 1 + (lost / cnt) * ph * 0.35,
                                       fill=RED, stipple="gray50", outline="")

            # contiguous runs of buckets with at least one reply; a gap means the app was not running
            runs, run, prev_b = [], [], None
            for b, mn, av, mx, _cnt, _lost in rows:
                if av is None or (prev_b is not None and b != prev_b + 1):
                    if run:
                        runs.append(run)
                        run = []
                if av is not None:
                    run.append((X(t0 + (b + 0.5) * width), Y(av), Y(mn), Y(mx), mx > ymax))
                prev_b = b
            if run:
                runs.append(run)

            for run in runs:
                if len(run) >= 2:
                    band = ([v for p in run for v in (p[0], p[3])]
                            + [v for p in reversed(run) for v in (p[0], p[2])])
                    c.create_polygon(band, fill=blend(PLOT_BG, CYAN, 0.35), stipple="gray50", outline="")
                    self._glow_line(c, [v for p in run for v in (p[0], p[1])], base=8)
                else:
                    px, py = run[0][0], run[0][1]
                    r = 2 * ui
                    c.create_oval(px - r, py - r, px + r, py + r, fill=CYAN, outline="")
                for p in run:
                    if p[4]:                                 # spike clipped at ymax
                        c.create_text(p[0], y0 + 4 * ui, text="▲", anchor="n", fill=YELLOW, font=self.f_small)

            cnt, _mn, av, _mx, _lost = data["total"]
            if av is not None and av <= ymax:
                ya = Y(av)
                c.create_line(x0, ya, x1, ya, fill=MAGENTA, dash=(4, 4))
                c.create_text(x0 + 6 * ui, ya - 2, text=f"avg {av:.1f}", anchor="sw",
                              fill=MAGENTA, font=self.f_small)

        self._draw_overlay(c, x0, y0, x1, y1)

        cnt, mn, av, mx, lost = data["total"]
        lost = lost or 0
        if cnt:
            coverage = 100.0 * len(rows) / data["buckets"]
            summary = (f"{days}D HISTORY // {target}   |   {cnt:,} probes   |   min {fmt_ms(mn)}   |   "
                       f"avg {fmt_ms(av, 1)}   |   max {fmt_ms(mx)}   |   loss {100.0 * lost / cnt:.2f} %   |   "
                       f"coverage {coverage:.0f} %")
        else:
            summary = f"{days}D HISTORY // {target}   |   no probes recorded"
        c.create_text(x0 + 10 * ui, y0 + 8 * ui, text=summary, anchor="nw", fill=CYAN_MID, font=self.f_small)
        c.create_text(x1 - 10 * ui, y1 - 6 * ui,
                      text=f"▬ avg   ░ min-max band   ▮ loss (from top)   ▲ clipped spike   |   "
                           f"bucket {width / 60:.1f} min",
                      anchor="se", fill=MUTED, font=self.f_small)


def main():
    if IS_WIN:                                   # crisp text on high-DPI displays
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
    app = NeonPing()
    app.mainloop()


if __name__ == "__main__":
    main()
