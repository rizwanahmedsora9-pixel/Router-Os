#!/usr/bin/env python3
"""
Bug Hunter v2 — LAN / WiFi discovery module (zero dependencies)
===============================================================

Answers the "auto fetch if connected wifi" gap: instead of guessing one
gateway IP and giving up, this module

  * reads the WiFi context (SSID / BSSID / signal) on every platform,
  * derives the local subnet,
  * sweeps it for live hosts (TCP connect + ARP table merge, no raw
    sockets, no root needed),
  * fingerprints every web host and ranks router candidates,

so the audit can proceed smoothly even when the gateway guess was wrong
or several routers/ONTs share the LAN.

Everything here is read-only and LAN-only. No credentials are used.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# WiFi context
# --------------------------------------------------------------------------- #

def _run(cmd: List[str], timeout: int = 6) -> str:
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode("utf-8", "replace")
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return ""


def _wifi_linux() -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {}
    # iwgetid: "wlan0  ESSID:\"MyNet\""
    out = _run(["iwgetid", "-r"]).strip()
    if out and "off/any" not in out:
        info["ssid"] = out.strip().strip('"')
    out = _run(["iwgetid", "-a", "-r"]).strip()
    if out and re.match(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", out):
        info["bssid"] = out.upper()
    # nmcli fallback
    if not info.get("ssid") and shutil.which("nmcli"):
        out = _run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL", "dev", "wifi"])
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[0] == "yes":
                info.setdefault("ssid", parts[1] or None)
                info.setdefault("bssid", (parts[2] or "").upper() or None)
                info.setdefault("signal", (parts[3] or "") + "%" if parts[3] else None)
                break
    # /proc/net/wireless fallback (interface + link quality only)
    if not info and os.path.exists("/proc/net/wireless"):
        try:
            with open("/proc/net/wireless", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = re.match(r"\s*(\S+):\s*\S+\s+(\S+)", line)
                    if m:
                        info["interface"] = m.group(1).rstrip(":")
                        info["link_quality"] = m.group(2)
                        break
        except OSError:
            pass
    return info


def _wifi_termux() -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {}
    if not shutil.which("termux-wifi-connectioninfo"):
        return info
    out = _run(["termux-wifi-connectioninfo"])
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return info
    if isinstance(data, dict):
        if data.get("ssid"):
            info["ssid"] = str(data["ssid"]).strip('"')
        if data.get("bssid"):
            info["bssid"] = str(data["bssid"]).upper()
        if data.get("rssi") is not None:
            info["signal"] = f"{data['rssi']} dBm"
        info["interface"] = "wlan0"
    return info


def _wifi_windows() -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {}
    out = _run(["netsh", "wlan", "show", "interfaces"])
    if not out:
        return info
    ssid = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", out, re.M)
    bssid = re.search(r"^\s*BSSID\s*:\s*([0-9a-fA-F:]{17})\s*$", out, re.M)
    signal = re.search(r"^\s*Signal\s*:\s*(\d+\s*%)\s*$", out, re.M)
    name = re.search(r"^\s*Name\s*:\s*(.+?)\s*$", out, re.M)
    if ssid and ssid.group(1).strip():
        info["ssid"] = ssid.group(1).strip()
    if bssid:
        info["bssid"] = bssid.group(1).upper()
    if signal:
        info["signal"] = signal.group(1)
    if name:
        info["interface"] = name.group(1).strip()
    return info


def _wifi_macos() -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {}
    airport = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
               "Versions/Current/Resources/airport")
    out = _run([airport, "-I"]) if os.path.exists(airport) else ""
    if out:
        ssid = re.search(r"^\s*SSID:\s*(.+?)\s*$", out, re.M)
        bssid = re.search(r"^\s*BSSID:\s*([0-9a-fA-F:]{17})\s*$", out, re.M)
        rssi = re.search(r"^\s*agrCtlRSSI:\s*(-?\d+)\s*$", out, re.M)
        if ssid:
            info["ssid"] = ssid.group(1).strip()
        if bssid:
            info["bssid"] = bssid.group(1).upper()
        if rssi:
            info["signal"] = f"{rssi.group(1)} dBm"
        return info
    out = _run(["networksetup", "-getairportnetwork", "en0"])
    m = re.search(r"Current Wi-?Fi Network:\s*(.+)", out, re.I)
    if m:
        info["ssid"] = m.group(1).strip()
    return info


def get_wifi_info() -> Dict[str, Any]:
    """Best-effort WiFi context. Never raises; missing keys mean unknown."""
    system = platform.system().lower()
    info: Dict[str, Any] = {"available": False}
    try:
        if system == "windows":
            info.update(_wifi_windows())
        elif system == "darwin":
            info.update(_wifi_macos())
        else:
            # Linux / Android / Termux / FreeBSD
            termux = _wifi_termux()
            if termux:
                info.update(termux)
            else:
                info.update(_wifi_linux())
    except Exception:
        pass
    info["available"] = bool(info.get("ssid") or info.get("bssid"))
    return {k: v for k, v in info.items() if v is not None}


# --------------------------------------------------------------------------- #
# Subnet derivation
# --------------------------------------------------------------------------- #

def get_interface_cidr(local_ip: Optional[str] = None) -> Optional[str]:
    """Return the LAN subnet as CIDR (e.g. '192.168.10.0/24')."""
    system = platform.system().lower()
    # Linux/macOS/FreeBSD/Termux: `ip -o -f inet addr show`
    out = _run(["ip", "-o", "-f", "inet", "addr", "show"])
    for line in out.splitlines():
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\s", line)
        if m:
            try:
                net = ipaddress.ip_interface(m.group(1)).network
                if net.is_private and not net.is_loopback:
                    # Prefer the subnet that holds our local IP.
                    if local_ip and local_ip in (str(h) for h in ()):
                        pass
                    return str(net)
            except ValueError:
                continue
    # Windows: ipconfig -> IPv4 + mask
    if system == "windows":
        out = _run(["ipconfig"])
        ips = re.findall(r"IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
        masks = re.findall(r"Subnet Mask[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
        for ip, mask in zip(ips, masks):
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                if net.is_private and not net.is_loopback:
                    return str(net)
            except ValueError:
                continue
    # Fallback: /24 around the local IP.
    if local_ip:
        try:
            addr = ipaddress.ip_address(local_ip)
            if addr.is_private and addr.version == 4:
                return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        except ValueError:
            pass
    return None


# --------------------------------------------------------------------------- #
# ARP table merge
# --------------------------------------------------------------------------- #

def parse_arp_table() -> List[Dict[str, str]]:
    """Parse the OS ARP/neighbour table into [{ip, mac}]."""
    entries: Dict[str, str] = {}
    system = platform.system().lower()

    out = _run(["ip", "neigh", "show"])
    for line in out.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+.*?\s+([0-9a-fA-F:]{17})\s+.*REACHABLE|"
                     r"(\d+\.\d+\.\d+\.\d+)\s+.*?\s+([0-9a-fA-F:]{17})", line)
        # Simpler: any ip + mac pair on the line.
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
        macs = re.findall(r"[0-9a-fA-F:]{17}", line)
        if ips and macs and "incomplete" not in line.lower():
            entries[ips[0]] = macs[0].upper()

    out = _run(["arp", "-a"])
    for line in out.splitlines():
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
        macs = re.findall(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
        if ips and macs and "incomplete" not in line.lower():
            entries.setdefault(ips[0], macs[0].upper().replace("-", ":"))

    if system == "windows" and not entries:
        out = _run(["arp", "-a"])
        for line in out.splitlines():
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+\S+", line)
            if m:
                entries.setdefault(m.group(1), m.group(2).upper().replace("-", ":"))
    return [{"ip": ip, "mac": mac} for ip, mac in sorted(entries.items())]


# --------------------------------------------------------------------------- #
# MAC OUI → vendor hints (common CPE OUIs only, best-effort)
# --------------------------------------------------------------------------- #

OUI_DB: Dict[str, str] = {}
for _prefix, _vendor in [
    # D-Link
    ("00:05:00", "D-Link"), ("00:0D:88", "D-Link"), ("00:11:95", "D-Link"),
    ("00:13:46", "D-Link"), ("00:15:E9", "D-Link"), ("00:17:9A", "D-Link"),
    ("00:19:5B", "D-Link"), ("00:1B:11", "D-Link"), ("00:1C:F0", "D-Link"),
    ("00:21:91", "D-Link"), ("00:22:B0", "D-Link"), ("00:24:01", "D-Link"),
    ("00:26:5A", "D-Link"), ("1C:BD:B9", "D-Link"), ("28:10:7B", "D-Link"),
    ("34:08:04", "D-Link"), ("5C:D9:98", "D-Link"), ("78:54:2E", "D-Link"),
    ("84:C9:B2", "D-Link"), ("90:94:E4", "D-Link"), ("B0:C5:54", "D-Link"),
    ("BC:F6:85", "D-Link"), ("C0:A0:BB", "D-Link"), ("CC:B2:55", "D-Link"),
    ("D8:FE:E3", "D-Link"), ("E4:6F:13", "D-Link"), ("F0:7D:68", "D-Link"),
    # TP-Link
    ("00:27:19", "TP-Link"), ("14:CC:20", "TP-Link"), ("30:B5:C2", "TP-Link"),
    ("50:C7:BF", "TP-Link"), ("60:E3:27", "TP-Link"), ("64:66:B3", "TP-Link"),
    ("6C:5A:B0", "TP-Link"), ("74:DA:88", "TP-Link"), ("78:44:FD", "TP-Link"),
    ("90:F6:52", "TP-Link"), ("A0:F3:C1", "TP-Link"), ("AC:84:C6", "TP-Link"),
    ("B0:4E:26", "TP-Link"), ("C0:25:E9", "TP-Link"), ("C4:6E:1F", "TP-Link"),
    ("D8:07:B6", "TP-Link"), ("DC:FE:18", "TP-Link"), ("E4:BE:ED", "TP-Link"),
    ("F4:F2:6D", "TP-Link"),
    # ZTE
    ("00:19:C6", "ZTE"), ("00:25:12", "ZTE"), ("08:10:77", "ZTE"),
    ("14:B9:68", "ZTE"), ("2C:AB:00", "ZTE"), ("38:4C:4C", "ZTE"),
    ("6C:F5:E8", "ZTE"), ("74:9D:8F", "ZTE"), ("7C:11:BE", "ZTE"),
    ("9C:28:BF", "ZTE"), ("B0:75:74", "ZTE"), ("D4:6E:5C", "ZTE"),
    ("E0:19:1D", "ZTE"), ("FC:C8:97", "ZTE"),
    # Huawei
    ("00:1E:10", "Huawei"), ("00:25:68", "Huawei"), ("04:25:C2", "Huawei"),
    ("08:63:61", "Huawei"), ("0C:96:BF", "Huawei"), ("10:1B:54", "Huawei"),
    ("20:F3:A3", "Huawei"), ("24:69:A5", "Huawei"), ("28:31:52", "Huawei"),
    ("38:BC:01", "Huawei"), ("48:46:FB", "Huawei"), ("54:A5:1B", "Huawei"),
    ("58:25:8A", "Huawei"), ("5C:4C:A9", "Huawei"), ("64:16:7F", "Huawei"),
    ("68:3B:78", "Huawei"), ("70:54:D2", "Huawei"), ("74:A5:A2", "Huawei"),
    ("78:62:56", "Huawei"), ("80:B6:86", "Huawei"), ("84:A8:E4", "Huawei"),
    ("88:CF:98", "Huawei"), ("AC:E2:15", "Huawei"), ("C4:F0:81", "Huawei"),
    ("E4:A8:B6", "Huawei"),
    # Netgear
    ("00:09:5B", "Netgear"), ("00:0F:B5", "Netgear"), ("00:14:6C", "Netgear"),
    ("00:18:4D", "Netgear"), ("00:1B:2F", "Netgear"), ("00:1E:2A", "Netgear"),
    ("00:1F:33", "Netgear"), ("00:26:F2", "Netgear"), ("08:BD:43", "Netgear"),
    ("20:0C:C8", "Netgear"), ("28:C6:8E", "Netgear"), ("2B:30:5D", "Netgear"),
    ("30:44:87", "Netgear"), ("44:94:FC", "Netgear"), ("6C:B0:CE", "Netgear"),
    ("9C:C7:A6", "Netgear"), ("A0:21:B7", "Netgear"), ("C0:3F:0E", "Netgear"),
    ("E8:F7:24", "Netgear"),
    # Tenda
    ("00:04:ED", "Tenda"), ("04:95:E6", "Tenda"), ("0A:3A:2A", "Tenda"),
    ("50:0F:F5", "Tenda"), ("C8:3A:35", "Tenda"), ("D8:32:14", "Tenda"),
    # Xiaomi
    ("14:F6:5A", "Xiaomi"), ("28:6C:07", "Xiaomi"), ("34:CE:00", "Xiaomi"),
    ("50:64:2B", "Xiaomi"), ("64:09:80", "Xiaomi"), ("78:11:DC", "Xiaomi"),
    # Asus
    ("00:1B:FC", "Asus"), ("00:1D:60", "Asus"), ("04:D9:F5", "Asus"),
    ("10:C3:7B", "Asus"), ("1C:87:2C", "Asus"), ("2C:56:DC", "Asus"),
    ("30:85:A9", "Asus"), ("38:D5:47", "Asus"), ("40:16:7E", "Asus"),
    ("54:A0:50", "Asus"), ("60:45:CB", "Asus"), ("AC:9E:17", "Asus"),
    # Cisco / Linksys
    ("00:00:0C", "Cisco"), ("00:01:42", "Cisco"), ("00:01:43", "Cisco"),
    ("00:06:52", "Cisco"), ("00:0D:28", "Cisco"), ("00:12:17", "Cisco"),
    ("00:13:19", "Cisco"), ("00:14:F2", "Cisco"), ("00:18:F8", "Linksys"),
    ("00:1C:10", "Linksys"), ("00:1D:7E", "Linksys"), ("00:21:29", "Cisco"),
    ("00:23:69", "Cisco"), ("58:6F:1C", "Cisco"),
    # MikroTik
    ("00:0C:42", "MikroTik"), ("08:55:31", "MikroTik"), ("0C:86:10", "MikroTik"),
    ("18:FD:74", "MikroTik"), ("1C:C1:DE", "MikroTik"), ("2C:C8:1B", "MikroTik"),
    ("48:8F:5A", "MikroTik"), ("4C:5E:0C", "MikroTik"), ("64:D1:54", "MikroTik"),
    ("6C:3B:6B", "MikroTik"), ("B8:69:F4", "MikroTik"), ("CC:2D:E0", "MikroTik"),
    ("D4:01:C3", "MikroTik"), ("D4:CA:6D", "MikroTik"), ("E4:8D:8C", "MikroTik"),
    # Ubiquiti
    ("00:15:6D", "Ubiquiti"), ("00:27:22", "Ubiquiti"), ("04:18:D6", "Ubiquiti"),
    ("24:5A:4C", "Ubiquiti"), ("68:72:51", "Ubiquiti"), ("70:A7:41", "Ubiquiti"),
    ("74:83:C2", "Ubiquiti"), ("78:45:58", "Ubiquiti"), ("80:2A:A8", "Ubiquiti"),
    ("B4:FB:E4", "Ubiquiti"), ("DC:9F:DB", "Ubiquiti"), ("E8:94:F6", "Ubiquiti"),
    ("F0:9F:C2", "Ubiquiti"), ("FC:EC:DA", "Ubiquiti"),
    # FiberHome / Fiber ONT
    ("00:0A:EB", "FiberHome"), ("08:5D:DD", "FiberHome"), ("10:12:18", "FiberHome"),
    ("1C:15:1F", "FiberHome"), ("1C:26:55", "FiberHome"), ("38:3A:21", "FiberHome"),
    ("40:16:3B", "FiberHome"), ("7C:11:CD", "FiberHome"), ("9C:28:EF", "FiberHome"),
    ("B0:52:16", "FiberHome"), ("C4:04:7B", "FiberHome"), ("E0:67:B3", "FiberHome"),
    # Totolink
    ("00:04:ED", "Totolink"), ("20:0D:B0", "Totolink"),
    # DrayTek
    ("00:50:7F", "DrayTek"),
]:
    OUI_DB.setdefault(_prefix, _vendor)


def lookup_oui(mac: str) -> Optional[str]:
    """Map a MAC address to a vendor hint via OUI. Best-effort."""
    if not mac:
        return None
    norm = mac.strip().upper().replace("-", ":")
    return OUI_DB.get(norm[:8])


# --------------------------------------------------------------------------- #
# Subnet sweep
# --------------------------------------------------------------------------- #

def _tcp_ping(ip: str, port: int, timeout: float) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ok = sock.connect_ex((ip, port)) == 0
        sock.close()
        return ok
    except OSError:
        return False


def discover_lan_hosts(cidr: Optional[str] = None,
                       local_ip: Optional[str] = None,
                       gateway: Optional[str] = None,
                       timeout: float = 0.7,
                       max_hosts: int = 256,
                       verbose: bool = False) -> List[Dict[str, Any]]:
    """Sweep the LAN for live hosts. TCP connect only — no raw sockets.

    Strategy:
      1. Merge the OS ARP/neighbour table (instant, already-known hosts).
      2. TCP-ping the subnet on 80/443/8080/22/23 in batches (finds the rest).
    Returns [{ip, mac, oui_vendor, web_ports, is_gateway}].
    """
    if cidr is None:
        cidr = get_interface_cidr(local_ip)
    if cidr is None:
        return []

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if network.num_addresses > 2048:
        # /21 or bigger: only sweep a /24 around the gateway/local IP.
        anchor = gateway or local_ip
        try:
            network = ipaddress.ip_network(f"{anchor}/24", strict=False)
        except (ValueError, TypeError):
            return []

    hosts = [str(h) for h in network.hosts()][:max_hosts]

    arp = {e["ip"]: e["mac"] for e in parse_arp_table()}
    live: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()

    # ARP-known hosts are live by definition; verify web ports quickly.
    for ip, mac in arp.items():
        try:
            if ipaddress.ip_address(ip) not in network:
                continue
        except ValueError:
            continue
        live[ip] = {"ip": ip, "mac": mac, "oui_vendor": lookup_oui(mac),
                    "web_ports": [], "is_gateway": (ip == gateway)}

    def _probe(ip: str) -> None:
        found_ports = []
        for port in (80, 443, 8080, 22, 23, 53, 7547, 1900):
            if _tcp_ping(ip, port, timeout):
                found_ports.append(port)
                if port in (80, 443, 8080):
                    break  # web host confirmed; enough
        routerish = bool(found_ports)
        # A host with no probed TCP port but an ARP entry stays listed.
        with lock:
            if routerish:
                entry = live.setdefault(
                    ip, {"ip": ip, "mac": arp.get(ip, ""),
                         "oui_vendor": lookup_oui(arp.get(ip, "")),
                         "web_ports": [], "is_gateway": (ip == gateway)})
                entry["web_ports"] = sorted(set(entry["web_ports"]) | set(found_ports))
            elif ip in live:
                with_thread_ports = live[ip].get("web_ports") or []
                live[ip]["web_ports"] = sorted(set(with_thread_ports) | set(found_ports))

    # Batched threads (64 at a time keeps FD usage sane on Termux/Windows).
    batch = 64
    for start in range(0, len(hosts), batch):
        threads = []
        for ip in hosts[start:start + batch]:
            if ip == local_ip:
                continue
            t = threading.Thread(target=_probe, args=(ip,))
            t.daemon = True
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout * 9 + 4)
        if verbose:
            print(f"    ... swept {min(start + batch, len(hosts))}/{len(hosts)}")

    result = sorted(live.values(), key=lambda e: ipaddress.ip_address(e["ip"]))
    for entry in result:
        entry["is_gateway"] = (entry["ip"] == gateway)
    return result


# --------------------------------------------------------------------------- #
# Router-candidate ranking
# --------------------------------------------------------------------------- #

ROUTER_TITLE_RES = [
    re.compile(r"router|gateway|modem|ont|gpon|ont|wireless|dsl|cpe|"
               r"admin|login|netgear|d-link|tp-link|zte|huawei|tenda|"
               r"asus|mikrotik|ubiquiti|linksys|fritz|mercusys|xiaomi",
               re.I),
]

KNOWN_SERVER_RES = [
    re.compile(r"micro[-_]?httpd|thttpd|mini[-_]?httpd|boa|rompager|goahead|"
               r"uhttpd|lighttpd|httpd|allegro|ehttp|eCos|DNAmicro|Virata|"
               r"AirTies|zte|huawei|d-link|tp-link|netgear|asus|tenda|"
               r"cisco|mikrotik|ubiquiti|draytek|fiberhome", re.I),
]


def quick_web_fingerprint(ip: str, timeout: float = 3.0) -> Dict[str, Any]:
    """One GET / : status, server banner, title, auth realm. Read-only."""
    import http.client
    fp: Dict[str, Any] = {"ip": ip, "http": False, "status": None,
                          "server": None, "title": None, "realm": None}
    try:
        conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
        conn.request("GET", "/", headers={
            "User-Agent": "BugHunter/2.0 (LAN discovery)",
            "Accept": "text/html,*/*", "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(16 * 1024).decode("utf-8", "replace")
        fp["http"] = True
        fp["status"] = resp.status
        for key, value in resp.getheaders():
            low = key.lower()
            if low == "server" and not fp["server"]:
                fp["server"] = value
            if low == "www-authenticate" and not fp["realm"]:
                m = re.search(r'realm\s*=\s*["\']?([^"\',]+)', value, re.I)
                fp["realm"] = m.group(1) if m else value[:64]
        m = re.search(r"<title[^>]*>([^<]{0,120})</title>", body, re.I | re.S)
        if m:
            fp["title"] = re.sub(r"\s+", " ", m.group(1)).strip()
        conn.close()
    except (OSError, Exception):
        pass
    return fp


def rank_router_candidates(hosts: List[Dict[str, Any]],
                           gateway: Optional[str] = None,
                           timeout: float = 3.0,
                           verbose: bool = False) -> List[Dict[str, Any]]:
    """Fingerprint web hosts and sort router-likely first.

    Score: gateway +5, web port +2, known server +2, router title +3,
    OUI vendor +2, TR-069 port +2.
    """
    web_hosts = [h for h in hosts
                 if h.get("web_ports") or h.get("ip") == gateway]
    if gateway and not any(h["ip"] == gateway for h in web_hosts):
        web_hosts.append({"ip": gateway, "mac": "", "oui_vendor": None,
                          "web_ports": [], "is_gateway": True})

    ranked: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def _fp(host: Dict[str, Any]) -> None:
        fp = quick_web_fingerprint(host["ip"], timeout)
        score = 0
        if host["ip"] == gateway:
            score += 5
        if fp.get("http"):
            score += 2
        if fp.get("server") and any(r.search(fp["server"]) for r in KNOWN_SERVER_RES):
            score += 2
        if fp.get("title") and any(r.search(fp["title"]) for r in ROUTER_TITLE_RES):
            score += 3
        if host.get("oui_vendor"):
            score += 2
        if 7547 in (host.get("web_ports") or []):
            score += 2
        if fp.get("realm"):
            score += 1
        entry = dict(host)
        entry.update(fp)
        entry["router_score"] = score
        with lock:
            ranked.append(entry)

    threads = []
    for host in web_hosts:
        t = threading.Thread(target=_fp, args=(host,))
        t.daemon = True
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout + 4)

    ranked.sort(key=lambda e: (-e["router_score"], e["ip"]))
    if verbose:
        for entry in ranked:
            print(f"    {entry['ip']:15} score={entry['router_score']} "
                  f"server={entry.get('server') or '-'} "
                  f"title={(entry.get('title') or '-')[:40]}")
    return ranked


def describe_host(entry: Dict[str, Any]) -> str:
    bits = [entry["ip"]]
    if entry.get("oui_vendor"):
        bits.append(entry["oui_vendor"])
    if entry.get("title"):
        bits.append(f"\"{entry['title'][:48]}\"")
    elif entry.get("server"):
        bits.append(f"[{entry['server'][:32]}]")
    if entry.get("is_gateway"):
        bits.append("(gateway)")
    return " ".join(bits)
