#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netdiag - ネットワーク診断デスクトップアプリ
標準ライブラリ + tkinter のみ。pip依存なし。
PyInstaller: pyinstaller --onefile --windowed netdiag.py
"""
import socket
import subprocess
import platform
import re
import threading
import queue
import time
import locale
import ipaddress
import urllib.request
import ssl
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog

APP_TITLE = "netdiag — ネットワーク診断"
IS_WINDOWS = platform.system() == "Windows"

# ---------------------------------------------------------------------------
# 共通ヘルパー
# ---------------------------------------------------------------------------

def decode_bytes(b: bytes) -> str:
    """OSロケール混在を想定したゆるいデコード(日本語WindowsのCP932対策)。"""
    if b is None:
        return ""
    encs = ["utf-8", locale.getpreferredencoding(False) or "utf-8", "cp932", "latin-1"]
    seen = set()
    for enc in encs:
        if not enc or enc.lower() in seen:
            continue
        seen.add(enc.lower())
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", "replace")


def get_local_ip() -> str:
    """送信せずローカルIPを推定(UDPソケットのトリック)。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def default_cidr() -> str:
    ip = get_local_ip()
    try:
        net = ipaddress.ip_network(ip + "/24", strict=False)
        return str(net)
    except Exception:
        return "192.168.1.0/24"


def parse_ports(spec: str):
    """'22,80,443' や '1-1024' を混在で解釈してソート済みリストを返す。"""
    ports = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            for p in range(min(a, b), max(a, b) + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389,
                443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432,
                5900, 6379, 8000, 8080, 8443, 9000]
DISCOVERY_PORTS = (80, 443, 22, 445, 135, 139, 3389, 8080)

# ---------------------------------------------------------------------------
# 診断ロジック(GUI非依存・テスト可能)
# ---------------------------------------------------------------------------

def dns_lookup(host: str):
    """getaddrinfo + 逆引き。(records, ptr) を返す。"""
    infos = socket.getaddrinfo(host, None)
    records = sorted({
        ("IPv6" if fam == socket.AF_INET6 else "IPv4", sa[0])
        for (fam, _t, _p, _c, sa) in infos
    })
    ptr = None
    if records:
        try:
            ptr = socket.gethostbyaddr(records[0][1])[0]
        except Exception:
            ptr = None
    return records, ptr


def tcp_connect(host: str, port: int, timeout: float = 0.5):
    """接続成功なら経過ms、失敗ならNone。"""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.perf_counter() - start) * 1000.0
    except Exception:
        return None


def port_scan(host: str, ports, timeout=0.6, workers=200, on_progress=None, stop_event=None):
    open_ports = []
    total = len(ports)
    done = 0

    def check(p):
        if stop_event and stop_event.is_set():
            return None
        rtt = tcp_connect(host, p, timeout)
        return (p, rtt) if rtt is not None else None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(check, p) for p in ports]
        for fut in as_completed(futures):
            done += 1
            res = fut.result()
            if res:
                open_ports.append(res)
                if on_progress:
                    on_progress("found", res, done, total)
            if on_progress and done % 25 == 0:
                on_progress("progress", None, done, total)
            if stop_event and stop_event.is_set():
                break
    open_ports.sort(key=lambda x: x[0])
    return open_ports


def discover_hosts(cidr: str, ports=DISCOVERY_PORTS, timeout=0.5, workers=128,
                   on_progress=None, stop_event=None):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    total = len(hosts)
    done = 0
    found = []

    def check(ip):
        if stop_event and stop_event.is_set():
            return None
        for p in ports:
            if stop_event and stop_event.is_set():
                return None
            if tcp_connect(ip, p, timeout) is not None:
                name = None
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except Exception:
                    name = None
                return (ip, p, name)
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(check, ip) for ip in hosts]
        for fut in as_completed(futures):
            done += 1
            res = fut.result()
            if res:
                found.append(res)
                if on_progress:
                    on_progress("found", res, done, total)
            if on_progress and done % 16 == 0:
                on_progress("progress", None, done, total)
            if stop_event and stop_event.is_set():
                break
    found.sort(key=lambda x: tuple(int(o) for o in x[0].split(".")))
    return found


def http_latency(host="speed.cloudflare.com", port=443, count=4):
    rtts = []
    for _ in range(count):
        r = tcp_connect(host, port, timeout=3.0)
        if r is not None:
            rtts.append(r)
        time.sleep(0.1)
    return rtts


def speed_download(num_bytes=20_000_000):
    url = f"https://speed.cloudflare.com/__down?bytes={num_bytes}"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "netdiag"})
    start = time.perf_counter()
    total = 0
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            total += len(chunk)
    elapsed = max(time.perf_counter() - start, 1e-6)
    return (total * 8) / elapsed / 1e6, total, elapsed


def speed_upload(num_bytes=8_000_000):
    url = "https://speed.cloudflare.com/__up"
    ctx = ssl.create_default_context()
    payload = b"0" * num_bytes
    req = urllib.request.Request(url, data=payload, method="POST",
                                 headers={"User-Agent": "netdiag",
                                          "Content-Type": "application/octet-stream"})
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=40, context=ctx) as r:
        r.read()
    elapsed = max(time.perf_counter() - start, 1e-6)
    return (num_bytes * 8) / elapsed / 1e6, num_bytes, elapsed


def stream_command(cmd, on_line, on_done, on_start=None):
    """外部コマンドを起動し1行ずつコールバック。コマンド未導入もハンドリング。"""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
    except FileNotFoundError:
        on_line(f"[エラー] コマンドが見つかりません: {cmd[0]}")
        if cmd[0] == "traceroute":
            on_line("Linux では `sudo apt install traceroute` などで導入できます。")
        on_done(False)
        return
    except Exception as e:
        on_line(f"[エラー] {e}")
        on_done(False)
        return
    if on_start:
        on_start(proc)
    try:
        for raw in iter(proc.stdout.readline, b""):
            on_line(decode_bytes(raw).rstrip("\r\n"))
    finally:
        proc.stdout.close()
        proc.wait()
    on_done(proc.returncode == 0)


# ---------------------------------------------------------------------------
# MAC / ベンダー (OUI) 解決
# ---------------------------------------------------------------------------
# 同梱は「よく見かける/仮想環境」中心の小規模辞書。網羅は限定的なので、
# 完全な照会はオンライン (api.macvendors.com) のチェックを有効化して補う。
OUI_DB = {
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "24:0A:C4": "Espressif (ESP)", "30:AE:A4": "Espressif (ESP)", "84:F3:EB": "Espressif (ESP)",
    "3C:07:54": "Apple", "A4:83:E7": "Apple", "F0:18:98": "Apple", "AC:BC:32": "Apple",
    "DC:A9:04": "Apple", "00:1C:B3": "Apple",
    "00:50:F2": "Microsoft", "7C:1E:52": "Microsoft", "C8:3F:26": "Microsoft",
    "00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1B:21": "Intel", "3C:97:0E": "Intel", "A0:88:B4": "Intel",
    "00:E0:4C": "Realtek",
    "50:C7:BF": "TP-Link", "14:CC:20": "TP-Link", "EC:08:6B": "TP-Link",
    "00:1A:A1": "Cisco", "00:0A:41": "Cisco",
    "00:14:22": "Dell", "B8:CA:3A": "Dell", "18:03:73": "Dell",
    "3C:D9:2B": "HP/HPE", "70:5A:0F": "HP/HPE",
    "48:46:FB": "Huawei", "80:FB:06": "Huawei",
    "28:6C:07": "Xiaomi", "64:09:80": "Xiaomi",
    "F4:F5:E8": "Google", "54:60:09": "Google",
    "44:65:0D": "Amazon", "F0:27:2D": "Amazon",
    "00:09:BF": "Nintendo", "98:B6:E9": "Nintendo",
    "FC:0F:E6": "Sony",
}

_vendor_cache = {}
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
_MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")


def normalize_mac(s: str) -> str:
    parts = re.split(r"[:-]", s.strip())
    if len(parts) != 6:
        return ""
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return ""
    if all(o == 0 for o in octets):
        return ""
    return ":".join(f"{o:02X}" for o in octets)


def _parse_arp_text(text: str, table: dict):
    for line in text.splitlines():
        ipm = _IP_RE.search(line)
        macm = _MAC_RE.search(line)
        if ipm and macm:
            mac = normalize_mac(macm.group(1))
            if mac:
                table[ipm.group(1)] = mac


def get_arp_table() -> dict:
    """IP -> MAC のマップ。OS差を吸収。MACはローカルL2上の端末のみ取得可能。"""
    table = {}
    if not IS_WINDOWS:
        try:
            with open("/proc/net/arp") as f:
                _parse_arp_text(f.read(), table)
        except Exception:
            pass
    if not table:
        cmd = ["arp", "-a"] if IS_WINDOWS else ["ip", "neigh"]
        try:
            out = subprocess.run(cmd, capture_output=True, timeout=5)
            _parse_arp_text(decode_bytes(out.stdout), table)
        except Exception:
            pass
    if not table and not IS_WINDOWS:
        try:
            out = subprocess.run(["arp", "-a"], capture_output=True, timeout=5)
            _parse_arp_text(decode_bytes(out.stdout), table)
        except Exception:
            pass
    return table


def lookup_vendor(mac: str, allow_online: bool = False) -> str:
    if not mac:
        return ""
    prefix = mac[:8]
    if prefix in OUI_DB:
        return OUI_DB[prefix]
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]
    if allow_online:
        try:
            time.sleep(0.6)  # 無料APIのレート制限対策
            req = urllib.request.Request("https://api.macvendors.com/" + mac,
                                         headers={"User-Agent": "netdiag"})
            with urllib.request.urlopen(req, timeout=4) as r:
                name = r.read().decode("utf-8", "replace").strip()
            if name and not name.startswith("{"):
                _vendor_cache[prefix] = name
                return name
        except Exception:
            pass
    return "不明"


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class NetDiagApp:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.reach_proc = None
        root.title(APP_TITLE)
        root.geometry("760x620")
        root.minsize(640, 480)

        self._init_style()

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=(8, 0))
        self.nb = nb
        self._build_reach_tab(nb)
        self._build_speed_tab(nb)
        self._build_lan_tab(nb)

        self.status = tk.StringVar(value="準備完了")
        ttk.Label(root, textvariable=self.status, anchor="w",
                  relief="sunken").pack(fill="x", side="bottom")

        self.root.after(80, self._drain_queue)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        self.stop_event.set()
        if self.reach_proc and self.reach_proc.poll() is None:
            try:
                self.reach_proc.terminate()
            except Exception:
                pass
        self.root.destroy()

    def _init_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TButton", padding=6)
        style.configure("Run.TButton", padding=6)

    # ----- tab: 到達性 -----------------------------------------------------
    def _build_reach_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="到達性")
        self.reach_tab = f

        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text="ホスト / IP:").pack(side="left")
        self.reach_host = tk.StringVar(value="8.8.8.8")
        ttk.Entry(top, textvariable=self.reach_host, width=28).pack(side="left", padx=6)
        ttk.Button(top, text="Ping", command=self._do_ping).pack(side="left", padx=2)
        ttk.Button(top, text="DNS", command=self._do_dns).pack(side="left", padx=2)
        ttk.Button(top, text="Traceroute", command=self._do_trace).pack(side="left", padx=2)
        ttk.Button(top, text="停止", command=self._stop_reach).pack(side="left", padx=2)
        ttk.Button(top, text="クリア", command=lambda: self._clear(self.reach_out)).pack(side="right")

        self.reach_out = scrolledtext.ScrolledText(f, height=20, wrap="word",
                                                    font=("Consolas", 10))
        self.reach_out.pack(fill="both", expand=True, pady=(8, 0))

    def _do_ping(self):
        host = self.reach_host.get().strip()
        if not host:
            return
        # 連続ping(停止ボタンで終了)
        cmd = ["ping", "-t", host] if IS_WINDOWS else ["ping", host]
        self._run_stream_task(cmd, self.reach_out, f"ping {host} (連続)")

    def _stop_reach(self):
        proc = self.reach_proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
            self.status.set("停止しました")
        else:
            self.status.set("実行中の処理はありません")

    def _do_trace(self):
        host = self.reach_host.get().strip()
        if not host:
            return
        cmd = ["tracert", host] if IS_WINDOWS else ["traceroute", host]
        self._run_stream_task(cmd, self.reach_out, f"traceroute {host}")

    def _do_dns(self):
        host = self.reach_host.get().strip()
        if not host:
            return
        self._log(self.reach_out, f"--- DNS lookup: {host} ---")
        self._spawn(self._dns_worker, host)

    def _dns_worker(self, host):
        try:
            records, ptr = dns_lookup(host)
            for fam, addr in records:
                self.q.put(("log", self.reach_out, f"  {fam:5s} {addr}"))
            if ptr:
                self.q.put(("log", self.reach_out, f"  PTR   {ptr}"))
            self.q.put(("status", "DNS解決完了"))
        except Exception as e:
            self.q.put(("log", self.reach_out, f"[エラー] {e}"))
            self.q.put(("status", "DNS解決失敗"))

    # ----- tab: 速度測定 ---------------------------------------------------
    def _build_speed_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="速度測定")

        ttk.Button(f, text="計測開始 (Cloudflare)",
                   command=self._do_speed).pack(anchor="w")
        ttk.Label(f, text="対インターネット実効速度を計測します。",
                  foreground="#666").pack(anchor="w", pady=(2, 8))

        grid = ttk.Frame(f)
        grid.pack(fill="x", pady=6)
        self.lbl_lat = tk.StringVar(value="—")
        self.lbl_down = tk.StringVar(value="—")
        self.lbl_up = tk.StringVar(value="—")
        for i, (title, var) in enumerate([("レイテンシ", self.lbl_lat),
                                          ("ダウンロード", self.lbl_down),
                                          ("アップロード", self.lbl_up)]):
            cell = ttk.Frame(grid, relief="groove", padding=12)
            cell.grid(row=0, column=i, padx=6, sticky="nsew")
            grid.columnconfigure(i, weight=1)
            ttk.Label(cell, text=title, foreground="#666").pack()
            ttk.Label(cell, textvariable=var,
                      font=("Segoe UI", 16, "bold")).pack(pady=(4, 0))

        self.speed_out = scrolledtext.ScrolledText(f, height=12, wrap="word",
                                                    font=("Consolas", 10))
        self.speed_out.pack(fill="both", expand=True, pady=(8, 0))

    def _do_speed(self):
        self.lbl_lat.set("…"); self.lbl_down.set("…"); self.lbl_up.set("…")
        self._log(self.speed_out, "--- 速度計測開始 ---")
        self._spawn(self._speed_worker)

    def _speed_worker(self):
        try:
            self.q.put(("status", "レイテンシ計測中…"))
            rtts = http_latency()
            if rtts:
                avg = sum(rtts) / len(rtts)
                self.q.put(("set", self.lbl_lat, f"{avg:.0f} ms"))
                self.q.put(("log", self.speed_out, f"レイテンシ 平均 {avg:.1f} ms (n={len(rtts)})"))
            else:
                self.q.put(("set", self.lbl_lat, "失敗"))

            self.q.put(("status", "ダウンロード計測中…"))
            mbps, total, el = speed_download()
            self.q.put(("set", self.lbl_down, f"{mbps:.1f} Mbps"))
            self.q.put(("log", self.speed_out,
                        f"ダウンロード {mbps:.1f} Mbps  ({total/1e6:.1f} MB / {el:.1f}s)"))

            self.q.put(("status", "アップロード計測中…"))
            mbps, total, el = speed_upload()
            self.q.put(("set", self.lbl_up, f"{mbps:.1f} Mbps"))
            self.q.put(("log", self.speed_out,
                        f"アップロード {mbps:.1f} Mbps  ({total/1e6:.1f} MB / {el:.1f}s)"))
            self.q.put(("status", "計測完了"))
        except Exception as e:
            self.q.put(("log", self.speed_out, f"[エラー] {e}"))
            self.q.put(("status", "計測失敗"))

    # ----- tab: LANスキャン ------------------------------------------------
    def _build_lan_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="LANスキャン")

        row1 = ttk.Frame(f); row1.pack(fill="x")
        ttk.Label(row1, text="サブネット (CIDR):").pack(side="left")
        self.cidr = tk.StringVar(value=default_cidr())
        ttk.Entry(row1, textvariable=self.cidr, width=20).pack(side="left", padx=6)
        ttk.Button(row1, text="端末を発見", command=self._do_discover).pack(side="left", padx=2)
        ttk.Button(row1, text="停止", command=self._stop).pack(side="left", padx=2)
        ttk.Button(row1, text="CSV保存", command=self._export_csv).pack(side="left", padx=2)
        self.vendor_online = tk.BooleanVar(value=False)
        ttk.Checkbutton(row1, text="ベンダーをオンライン照会",
                        variable=self.vendor_online).pack(side="right")

        cols = ("ip", "host", "mac", "vendor", "port")
        headers = {"ip": "IP", "host": "ホスト名", "mac": "MAC",
                   "vendor": "ベンダー", "port": "応答Port"}
        widths = {"ip": 130, "host": 150, "mac": 150, "vendor": 150, "port": 70}
        self._tree_headers = headers
        self._sort_state = {}
        tree_frame = ttk.Frame(f)
        tree_frame.pack(fill="both", expand=True, pady=(8, 4))
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=10)
        for c in cols:
            self.tree.heading(c, text=headers[c],
                              command=lambda col=c: self._sort_tree(col))
            self.tree.column(c, width=widths[c],
                             anchor=("center" if c == "port" else "w"))
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._tree_to_scan)
        self.tree.bind("<Button-3>", self._show_tree_menu)

        self.tree_menu = tk.Menu(self.tree, tearoff=0)
        self.tree_menu.add_command(label="このIPにPing",
                                   command=lambda: self._send_to_reach("ping"))
        self.tree_menu.add_command(label="このIPにTraceroute",
                                   command=lambda: self._send_to_reach("trace"))
        self.tree_menu.add_command(label="このIPをDNS逆引き",
                                   command=lambda: self._send_to_reach("dns"))
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label="ポートスキャンに送る",
                                   command=lambda: self._tree_to_scan(None))
        self.tree_menu.add_command(label="IPをコピー", command=self._copy_selected_ip)

        self.lan_prog = ttk.Progressbar(f, mode="determinate")
        self.lan_prog.pack(fill="x", pady=(0, 6))

        ttk.Separator(f, orient="horizontal").pack(fill="x", pady=2)

        row2 = ttk.Frame(f); row2.pack(fill="x", pady=(6, 0))
        ttk.Label(row2, text="ポートスキャン対象:").pack(side="left")
        self.scan_host = tk.StringVar(value=get_local_ip())
        ttk.Entry(row2, textvariable=self.scan_host, width=18).pack(side="left", padx=6)
        ttk.Label(row2, text="ポート:").pack(side="left")
        self.scan_ports = tk.StringVar(value="1-1024")
        ttk.Entry(row2, textvariable=self.scan_ports, width=14).pack(side="left", padx=6)
        ttk.Button(row2, text="スキャン", command=self._do_portscan).pack(side="left", padx=2)

        self.scan_out = scrolledtext.ScrolledText(f, height=7, wrap="word",
                                                  font=("Consolas", 10))
        self.scan_out.pack(fill="x", pady=(6, 0))

    def _tree_to_scan(self, _event):
        ip = self._selected_ip()
        if ip:
            self.scan_host.set(ip)

    def _selected_ip(self):
        sel = self.tree.selection()
        return self.tree.set(sel[0], "ip") if sel else None

    def _show_tree_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        self.tree.focus(row)
        try:
            self.tree_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.tree_menu.grab_release()

    def _send_to_reach(self, action):
        ip = self._selected_ip()
        if not ip:
            return
        self.reach_host.set(ip)
        self.nb.select(self.reach_tab)
        if action == "ping":
            self._do_ping()
        elif action == "trace":
            self._do_trace()
        elif action == "dns":
            self._do_dns()

    def _copy_selected_ip(self):
        ip = self._selected_ip()
        if ip:
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.status.set(f"コピーしました: {ip}")

    def _export_csv(self):
        rows = self.tree.get_children("")
        if not rows:
            self.status.set("保存する発見結果がありません")
            return
        path = filedialog.asksaveasfilename(
            title="発見結果をCSVで保存",
            defaultextension=".csv",
            initialfile="netdiag_hosts.csv",
            filetypes=[("CSV", "*.csv"), ("すべて", "*.*")])
        if not path:
            return
        try:
            # Excel(日本語Windows)対策に BOM 付き UTF-8
            with open(path, "w", newline="", encoding="utf-8-sig") as fp:
                w = csv.writer(fp)
                w.writerow(["IP", "ホスト名", "MAC", "ベンダー", "応答Port"])
                for iid in rows:
                    w.writerow([self.tree.set(iid, c)
                                for c in ("ip", "host", "mac", "vendor", "port")])
            self.status.set(f"CSV保存: {path} ({len(rows)}件)")
        except Exception as e:
            self.status.set(f"CSV保存エラー: {e}")

    def _sort_tree(self, col):
        reverse = self._sort_state.get(col, False)
        items = [(self.tree.set(iid, col), iid)
                 for iid in self.tree.get_children("")]

        def key(pair):
            val = pair[0]
            if val in ("", "—"):
                return (1, ())  # 未取得は末尾へ
            if col == "ip":
                try:
                    return (0, tuple(int(o) for o in val.split(".")))
                except Exception:
                    return (0, (val,))
            if col == "port":
                try:
                    return (0, (int(val),))
                except Exception:
                    return (0, (val,))
            return (0, (val.lower(),))

        items.sort(key=key, reverse=reverse)
        for index, (_v, iid) in enumerate(items):
            self.tree.move(iid, "", index)
        self._sort_state[col] = not reverse
        for c, base in self._tree_headers.items():
            arrow = (" ▼" if reverse else " ▲") if c == col else ""
            self.tree.heading(c, text=base + arrow)

    def _do_discover(self):
        self.stop_event.clear()
        cidr = self.cidr.get().strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
        except Exception:
            self.status.set(f"不正なCIDR: {cidr}")
            return
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._sort_state = {}
        for c, base in self._tree_headers.items():
            self.tree.heading(c, text=base)
        self.status.set(f"端末発見開始: {cidr}")
        self.lan_prog["value"] = 0
        self._spawn(self._discover_worker, cidr, self.vendor_online.get())

    def _discover_worker(self, cidr, online):
        def cb(kind, res, done, total):
            if total:
                self.q.put(("prog", done / total * 100))
            if kind == "found":
                ip, port, name = res
                self.q.put(("tree_add", ip, (ip, name or "", "", "", port)))
            self.q.put(("status", f"発見スキャン {done}/{total}"))
        try:
            found = discover_hosts(cidr, on_progress=cb, stop_event=self.stop_event)
            self.q.put(("prog", 100))
            self.q.put(("status", f"MAC/ベンダー解決中… ({len(found)}台)"))
            arp = get_arp_table()
            for ip, _port, _name in found:
                mac = arp.get(ip, "")
                self.q.put(("tree_set", ip, "mac", mac or "—"))
                if mac:
                    vendor = lookup_vendor(mac, allow_online=online)
                    self.q.put(("tree_set", ip, "vendor", vendor))
                else:
                    self.q.put(("tree_set", ip, "vendor", "—"))
            self.q.put(("status", f"発見完了: {len(found)}台"))
        except Exception as e:
            self.q.put(("status", f"発見エラー: {e}"))

    def _do_portscan(self):
        self.stop_event.clear()
        host = self.scan_host.get().strip()
        try:
            ports = parse_ports(self.scan_ports.get())
        except Exception:
            self._log(self.scan_out, "[エラー] ポート指定が不正です")
            return
        if not host or not ports:
            return
        self._log(self.scan_out, f"--- ポートスキャン: {host} ({len(ports)}ポート) ---")
        self.lan_prog["value"] = 0
        self._spawn(self._portscan_worker, host, ports)

    def _portscan_worker(self, host, ports):
        def cb(kind, res, done, total):
            if total:
                self.q.put(("prog", done / total * 100))
            if kind == "found":
                p, rtt = res
                svc = SERVICES.get(p, "")
                self.q.put(("log", self.scan_out,
                            f"  open  {p:<6}{svc:<10}{rtt:.0f} ms"))
            self.q.put(("status", f"スキャン {done}/{total}"))
        try:
            res = port_scan(host, ports, on_progress=cb, stop_event=self.stop_event)
            self.q.put(("prog", 100))
            self.q.put(("log", self.scan_out, f"=> open ポート {len(res)} 個"))
            self.q.put(("status", "スキャン完了"))
        except Exception as e:
            self.q.put(("log", self.scan_out, f"[エラー] {e}"))

    def _stop(self):
        self.stop_event.set()
        self.status.set("停止要求…")

    # ----- 共通: スレッド/キュー ------------------------------------------
    def _spawn(self, fn, *args):
        threading.Thread(target=fn, args=args, daemon=True).start()

    def _run_stream_task(self, cmd, widget, label):
        # 既存の連続ping等が動いていれば止めてから開始
        if self.reach_proc and self.reach_proc.poll() is None:
            try:
                self.reach_proc.terminate()
            except Exception:
                pass
        self._log(widget, f"--- {label} ---")

        def on_start(proc):
            self.reach_proc = proc

        def on_line(line):
            self.q.put(("log", widget, line))

        def on_done(ok):
            self.reach_proc = None
            self.q.put(("status", f"{label} {'完了' if ok else '終了'}"))

        self._spawn(stream_command, cmd, on_line, on_done, on_start)

    def _log(self, widget, text):
        widget.insert("end", text + "\n")
        widget.see("end")

    def _clear(self, widget):
        widget.delete("1.0", "end")

    def _drain_queue(self):
        try:
            while True:
                item = self.q.get_nowait()
                kind = item[0]
                if kind == "log":
                    self._log(item[1], item[2])
                elif kind == "status":
                    self.status.set(item[1])
                elif kind == "set":
                    item[1].set(item[2])
                elif kind == "prog":
                    self.lan_prog["value"] = item[1]
                elif kind == "tree_add":
                    iid, values = item[1], item[2]
                    if self.tree.exists(iid):
                        self.tree.item(iid, values=values)
                    else:
                        self.tree.insert("", "end", iid=iid, values=values)
                elif kind == "tree_set":
                    iid, col, value = item[1], item[2], item[3]
                    if self.tree.exists(iid):
                        self.tree.set(iid, col, value)
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)


SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8000: "http", 8080: "http", 8443: "https",
    9000: "http",
}


def main():
    root = tk.Tk()
    NetDiagApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
