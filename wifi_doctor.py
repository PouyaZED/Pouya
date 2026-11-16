#!/usr/bin/env python3
"""
wifi_doctor.py - find out what is slowing down your Wi-Fi.

Run it on a laptop/desktop that is connected to the Wi-Fi you want to check:

    python3 wifi_doctor.py              # full check (~1-2 minutes)
    python3 wifi_doctor.py --quick      # skip the speed / bufferbloat tests
    python3 wifi_doctor.py --plan 500   # tell it your ISP plan (Mbps) for a better verdict

Works on Linux, macOS and Windows with only the Python standard library.
It does NOT log in to or change anything on your router. It only:
  * reads your computer's own Wi-Fi status (signal, channel, link rate, ...)
  * looks at nearby Wi-Fi networks to measure channel congestion
  * pings the router and the internet (latency, jitter, packet loss)
  * runs a short speed test against speed.cloudflare.com and measures
    latency under load (bufferbloat)
  * times DNS lookups through the router vs. public resolvers
  * asks the router for its model and WAN traffic counters via UPnP (if enabled)
  * lists the devices on your local network (ARP table)

At the end it prints a ranked list of everything it found that slows you down,
and writes the same report to wifi_report.md (and JSON with --json).
"""

import argparse
import ipaddress
import json
import os
import platform
import random
import re
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

OS = platform.system()  # "Linux", "Darwin", "Windows"
UA = {"User-Agent": "wifi-doctor/1.0"}
PUBLIC_HOSTS = ["1.1.1.1", "8.8.8.8"]
DOWN_URL = "https://speed.cloudflare.com/__down?bytes=50000000"
UP_URL = "https://speed.cloudflare.com/__up"
PUBLIC_DNS = {"Cloudflare 1.1.1.1": "1.1.1.1", "Google 8.8.8.8": "8.8.8.8", "Quad9 9.9.9.9": "9.9.9.9"}
DNS_TEST_NAMES = ["google.com", "youtube.com", "wikipedia.org", "amazon.com", "netflix.com",
                  "microsoft.com", "apple.com", "reddit.com"]

# --------------------------------------------------------------------------- helpers


def run(cmd, timeout=20):
    """Run a command and return its stdout ("" if it is missing or fails to start)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace", stdin=subprocess.DEVNULL)
        return p.stdout or ""
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return ""


def log(msg):
    print(f"  > {msg}", flush=True)


def lan_opener():
    """urllib opener that ignores any HTTP proxy (we are talking to the LAN)."""
    # Routers almost always use self-signed certificates for their admin page.
    # We only read the page title / model name and never send credentials.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                       urllib.request.HTTPSHandler(context=ctx))


def freq_to_channel(freq_mhz):
    f = int(round(float(freq_mhz)))
    if f == 2484:
        return 14, "2.4"
    if 2400 <= f < 2500:
        return (f - 2407) // 5, "2.4"
    if 5000 <= f < 5925:
        return (f - 5000) // 5, "5"
    if 5925 <= f <= 7125:
        return (f - 5950) // 5, "6"
    return None, None


def band_from_channel(ch):
    if ch is None:
        return None
    return "2.4" if ch <= 14 else "5"


def pct_to_dbm(pct):
    """Rough Windows/NetworkManager style conversion of signal quality % to dBm."""
    return int(round(pct / 2 - 100))


def phy_from_bitrate(line):
    if "EHT" in line:
        return "802.11be (Wi-Fi 7)"
    if "HE-" in line or " HE" in line:
        return "802.11ax (Wi-Fi 6/6E)"
    if "VHT" in line:
        return "802.11ac (Wi-Fi 5)"
    if "MCS" in line:
        return "802.11n (Wi-Fi 4)"
    return "802.11a/b/g (legacy)"


# --------------------------------------------------------------------------- latency


def ping_cmd(host, count, interval):
    if OS == "Windows":
        return ["ping", "-n", str(count), "-w", "1000", host]
    if OS == "Darwin":
        return ["ping", "-c", str(count), "-i", str(max(interval, 0.1)), "-W", "1000", host]
    return ["ping", "-n", "-c", str(count), "-i", str(max(interval, 0.2)), "-W", "1", host]


def parse_ping(text):
    """Return a list of RTTs (ms) from ping output on Linux/macOS/Windows (any language)."""
    vals = []
    for m in re.finditer(r"[=<]([\d]+(?:[.,]\d+)?)\s?ms\b", text):
        v = float(m.group(1).replace(",", "."))
        # Windows prints "time<1ms"
        if text[m.start()] == "<":
            v = v / 2
        vals.append(v)
    return vals


def summarize(vals, sent):
    if not sent:
        return None
    r = {"sent": sent, "received": len(vals),
         "loss_pct": round(100.0 * max(0, sent - len(vals)) / sent, 1)}
    if vals:
        s = sorted(vals)
        r.update({
            "min": round(s[0], 1),
            "avg": round(statistics.mean(s), 1),
            "median": round(statistics.median(s), 1),
            "p95": round(s[int(round(0.95 * (len(s) - 1)))], 1),
            "max": round(s[-1], 1),
            "jitter": round(statistics.mean(abs(a - b) for a, b in zip(vals, vals[1:])), 1)
            if len(vals) > 1 else 0.0,
        })
    return r


def tcp_ping(host, port, count, interval=0.2):
    vals = []
    for _ in range(count):
        t = time.perf_counter()
        try:
            socket.create_connection((host, port), timeout=1.5).close()
            vals.append((time.perf_counter() - t) * 1000)
        except ConnectionRefusedError:  # the host answered with RST -> still a valid RTT
            vals.append((time.perf_counter() - t) * 1000)
        except OSError:
            pass
        time.sleep(interval)
    return vals


def measure_latency(host, count=20, interval=0.2, tcp_port=443):
    if OS == "Windows":
        count = max(5, min(count, 15))  # Windows ping is fixed at 1/s
    out = run(ping_cmd(host, count, interval), timeout=count * 2 + 15)
    if out.strip():
        r = summarize(parse_ping(out), count)
        r["method"] = "icmp"
        return r
    # no ping binary / not permitted: fall back to TCP connect timing
    r = summarize(tcp_ping(host, tcp_port, count, interval), count)
    r["method"] = f"tcp/{tcp_port}"
    return r


# --------------------------------------------------------------------------- network basics


def parse_proc_net_route(text):
    best = None
    for line in text.splitlines()[1:]:
        p = line.split()
        if len(p) < 7 or p[1] != "00000000" or not int(p[3], 16) & 2:
            continue
        gw = socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
        metric = int(p[6])
        if best is None or metric < best[2]:
            best = (gw, p[0], metric)
    return (best[0], best[1]) if best else (None, None)


def parse_windows_route(text):
    best = None
    for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)",
                         text, re.M):
        if best is None or int(m.group(3)) < best[2]:
            best = (m.group(1), m.group(2), int(m.group(3)))
    return (best[0], best[1]) if best else (None, None)


def default_gateway():
    """Return (gateway_ip, interface_name_or_ip)."""
    if OS == "Linux":
        try:
            with open("/proc/net/route") as f:
                gw, itf = parse_proc_net_route(f.read())
            if gw:
                return gw, itf
        except OSError:
            pass
        m = re.search(r"default via (\S+) dev (\S+)", run(["ip", "route", "show", "default"]))
        if m:
            return m.group(1), m.group(2)
    elif OS == "Darwin":
        out = run(["route", "-n", "get", "default"])
        gw = re.search(r"gateway:\s*(\S+)", out)
        itf = re.search(r"interface:\s*(\S+)", out)
        return (gw.group(1) if gw else None), (itf.group(1) if itf else None)
    elif OS == "Windows":
        return parse_windows_route(run(["route", "print", "-4", "0.0.0.0"]))
    return None, None


def local_ip(target="1.1.1.1"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# --------------------------------------------------------------------------- Wi-Fi status (per OS)


def parse_iw_link(text):
    info = {}
    if "Not connected" in text:
        info["connected"] = False
        return info
    m = re.search(r"Connected to ([0-9a-fA-F:]{17})", text)
    if m:
        info["connected"] = True
        info["bssid"] = m.group(1).lower()
    m = re.search(r"SSID:\s*(.*)", text)
    if m:
        info["ssid"] = m.group(1).strip()
    m = re.search(r"freq:\s*([\d.]+)", text)
    if m:
        info["freq_mhz"] = int(float(m.group(1)))
        info["channel"], info["band"] = freq_to_channel(m.group(1))
    m = re.search(r"signal:\s*(-?\d+)", text)
    if m:
        info["rssi_dbm"] = int(m.group(1))
    for key in ("rx", "tx"):
        m = re.search(key + r" bitrate:\s*([\d.]+)\s*MBit/s(.*)", text)
        if m:
            info[f"{key}_rate_mbps"] = float(m.group(1))
            info.setdefault("phy", phy_from_bitrate(m.group(2)))
            w = re.search(r"(\d+)MHz", m.group(2))
            if w:
                info.setdefault("width_mhz", int(w.group(1)))
    return info


def parse_iw_info(text):
    info = {}
    m = re.search(r"channel\s+(\d+)\s+\((\d+)\s*MHz\)(?:,\s*width:\s*(\d+))?", text)
    if m:
        info["channel"] = int(m.group(1))
        info["band"] = freq_to_channel(m.group(2))[1]
        if m.group(3):
            info["width_mhz"] = int(m.group(3))
    m = re.search(r"txpower\s+([\d.]+)\s*dBm", text)
    if m:
        info["txpower_dbm"] = float(m.group(1))
    return info


def split_nmcli(line):
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in re.split(r"(?<!\\):", line)]


def parse_nmcli(text):
    """Parse `nmcli -t -e yes -f IN-USE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY dev wifi list`."""
    current, neighbors = {}, []
    for line in text.splitlines():
        p = split_nmcli(line)
        if len(p) < 8:
            continue
        in_use, ssid, bssid, chan, freq, rate, signal, sec = p[:8]
        try:
            ch = int(chan)
        except ValueError:
            continue
        fm = re.search(r"(\d+)", freq)
        band = freq_to_channel(fm.group(1))[1] if fm else band_from_channel(ch)
        sig = int(signal) if signal.isdigit() else None
        entry = {"ssid": ssid, "bssid": bssid.lower(), "channel": ch, "band": band,
                 "signal_pct": sig, "rssi_dbm": pct_to_dbm(sig) if sig is not None else None,
                 "security": sec}
        if in_use.strip() == "*":
            current = dict(entry)
            rm = re.search(r"([\d.]+)", rate)
            if rm:
                current["tx_rate_mbps"] = float(rm.group(1))
            current["connected"] = True
        else:
            neighbors.append(entry)
    return current, neighbors


def wifi_linux(iface_hint=None):
    ifaces = re.findall(r"Interface\s+(\S+)", run(["iw", "dev"]))
    if not ifaces and os.path.isdir("/sys/class/net"):
        ifaces = [n for n in os.listdir("/sys/class/net")
                  if os.path.isdir(f"/sys/class/net/{n}/wireless")]
    if not ifaces:
        return None, []
    iface = iface_hint if iface_hint in ifaces else ifaces[0]
    info = {"iface": iface}
    info.update(parse_iw_info(run(["iw", "dev", iface, "info"])))
    link = parse_iw_link(run(["iw", "dev", iface, "link"]))
    for k, v in link.items():
        if k == "width_mhz" and "width_mhz" in info:
            continue
        info[k] = v
    ps = re.search(r"Power save:\s*(\w+)", run(["iw", "dev", iface, "get", "power_save"]))
    if ps:
        info["power_save"] = ps.group(1).lower() == "on"
    nm_out = run(["nmcli", "-t", "-e", "yes", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY",
                  "dev", "wifi", "list", "ifname", iface], timeout=30)
    cur, neighbors = parse_nmcli(nm_out)
    for k, v in cur.items():
        info.setdefault(k, v)
    if cur.get("security"):
        info["security"] = cur["security"]
    if not neighbors and os.geteuid() == 0:
        neighbors = parse_iw_scan(run(["iw", "dev", iface, "scan"], timeout=30), info.get("bssid"))
    return info, neighbors


def parse_iw_scan(text, own_bssid=None):
    out = []
    for block in re.split(r"\nBSS ", "\n" + text)[1:]:
        m = re.match(r"([0-9a-fA-F:]{17})", block)
        bssid = m.group(1).lower() if m else ""
        if own_bssid and bssid == own_bssid:
            continue
        f = re.search(r"freq:\s*([\d.]+)", block)
        s = re.search(r"signal:\s*(-?[\d.]+)", block)
        n = re.search(r"SSID:\s*(.*)", block)
        if not f:
            continue
        ch, band = freq_to_channel(f.group(1))
        out.append({"ssid": n.group(1).strip() if n else "", "bssid": bssid, "channel": ch, "band": band,
                    "rssi_dbm": int(float(s.group(1))) if s else None})
    return out


def _parse_channel_str(val):
    s = str(val)
    ch = re.search(r"(\d+)", s)
    band = re.search(r"(2|5|6)\s*(?:\.4)?\s*GHz", s)
    width = re.search(r"(\d+)\s*MHz", s)
    ch = int(ch.group(1)) if ch else None
    b = band.group(1) if band else band_from_channel(ch)
    if b == "2":
        b = "2.4"
    return ch, b, (int(width.group(1)) if width else None)


def _parse_signal_noise(val):
    nums = re.findall(r"-?\d+", str(val))
    return (int(nums[0]) if nums else None), (int(nums[1]) if len(nums) > 1 else None)


def parse_macos_profiler(data):
    info, neighbors = None, []
    for top in data.get("SPAirPortDataType", []):
        for itf in top.get("spairport_airport_interfaces", []):
            cur = itf.get("spairport_current_network_information")
            if not cur:
                continue
            ch, band, width = _parse_channel_str(cur.get("spairport_network_channel", ""))
            rssi, noise = _parse_signal_noise(cur.get("spairport_signal_noise", ""))
            info = {"iface": itf.get("_name"), "connected": True, "ssid": cur.get("_name"),
                    "channel": ch, "band": band, "width_mhz": width, "rssi_dbm": rssi, "noise_dbm": noise,
                    "phy": cur.get("spairport_network_phymode"),
                    "security": str(cur.get("spairport_security_mode", "")).replace("spairport_security_mode_", ""),
                    "mcs": cur.get("spairport_network_mcs")}
            rate = cur.get("spairport_network_rate")
            if rate not in (None, ""):
                try:
                    info["tx_rate_mbps"] = float(rate)
                except (TypeError, ValueError):
                    pass
            for n in itf.get("spairport_airport_other_local_wireless_networks", []) or []:
                nch, nband, nwidth = _parse_channel_str(n.get("spairport_network_channel", ""))
                nrssi, _ = _parse_signal_noise(n.get("spairport_signal_noise", ""))
                neighbors.append({"ssid": n.get("_name", ""), "channel": nch, "band": nband,
                                  "width_mhz": nwidth, "rssi_dbm": nrssi,
                                  "security": str(n.get("spairport_security_mode", ""))
                                  .replace("spairport_security_mode_", "")})
            return info, neighbors
    return info, neighbors


def wifi_macos():
    out = run(["system_profiler", "-json", "SPAirPortDataType"], timeout=90)
    try:
        return parse_macos_profiler(json.loads(out))
    except ValueError:
        return None, []


def _kv_lines(text):
    for line in text.splitlines():
        m = re.match(r"^\s*([^:\r\n]+?)\s*:\s?(.*?)\s*$", line)
        if m:
            yield m.group(1).strip(), m.group(2).strip(), line


def parse_netsh_interfaces(text):
    kv = {}
    for k, v, _ in _kv_lines(text):
        if k.lower() == "name" and kv.get("name"):
            if kv.get("state", "").lower() == "connected":
                break  # keep the first connected interface
            kv = {}
        kv.setdefault(k.lower(), v)
    if not kv.get("ssid"):
        return None
    info = {"iface": kv.get("name"), "connected": kv.get("state", "").lower() == "connected",
            "ssid": kv.get("ssid"), "bssid": kv.get("bssid", "").lower(), "phy": kv.get("radio type"),
            "security": f"{kv.get('authentication', '')} {kv.get('cipher', '')}".strip()}
    if kv.get("channel", "").isdigit():
        info["channel"] = int(kv["channel"])
    band = re.search(r"([\d.]+)\s*GHz", kv.get("band", ""))
    info["band"] = (band.group(1) if band else band_from_channel(info.get("channel")))
    if info["band"] == "2":
        info["band"] = "2.4"
    for k, dst in (("receive rate (mbps)", "rx_rate_mbps"), ("transmit rate (mbps)", "tx_rate_mbps")):
        try:
            info[dst] = float(kv.get(k, "").replace(",", "."))
        except ValueError:
            pass
    sig = re.search(r"(\d+)", kv.get("signal", ""))
    if sig:
        info["signal_pct"] = int(sig.group(1))
    rssi = re.search(r"(-\d+)", kv.get("rssi", ""))
    if rssi:
        info["rssi_dbm"] = int(rssi.group(1))
    elif sig:
        info["rssi_dbm"] = pct_to_dbm(int(sig.group(1)))
        info["rssi_estimated"] = True
    return info


def parse_netsh_networks(text):
    out, ssid, sec, cur = [], "", "", None
    for k, v, line in _kv_lines(text):
        kl = k.lower()
        if re.match(r"^ssid \d+$", kl):
            ssid, sec = v, ""
        elif kl == "authentication":
            sec = v
        elif re.match(r"^bssid \d+$", kl):
            cur = {"ssid": ssid, "bssid": v.lower(), "security": sec}
            out.append(cur)
        elif cur is not None:
            if kl == "signal":
                m = re.search(r"(\d+)", v)
                if m:
                    cur["signal_pct"] = int(m.group(1))
                    cur["rssi_dbm"] = pct_to_dbm(cur["signal_pct"])
            elif kl == "channel" and v.isdigit():
                cur["channel"] = int(v)
            elif kl == "band":
                m = re.search(r"([\d.]+)\s*GHz", v)
                if m:
                    cur["band"] = "2.4" if m.group(1) in ("2", "2.4") else m.group(1)
            elif kl == "radio type":
                cur["phy"] = v
    for n in out:
        n.setdefault("band", band_from_channel(n.get("channel")))
    return out


def wifi_windows():
    info = parse_netsh_interfaces(run(["netsh", "wlan", "show", "interfaces"]))
    neighbors = parse_netsh_networks(run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=30))
    if info and info.get("bssid"):
        neighbors = [n for n in neighbors if n.get("bssid") != info["bssid"]]
    return info, neighbors


def wifi_status(iface_hint=None):
    try:
        if OS == "Linux":
            return wifi_linux(iface_hint)
        if OS == "Darwin":
            return wifi_macos()
        if OS == "Windows":
            return wifi_windows()
    except Exception as e:  # never let one probe kill the whole report
        log(f"Wi-Fi status probe failed: {e}")
    return None, []


# --------------------------------------------------------------------------- channel congestion

FIVE_GHZ_BLOCKS = [(36, 48), (52, 64), (100, 112), (116, 128), (132, 144), (149, 161), (165, 177)]


def five_block(ch):
    for lo, hi in FIVE_GHZ_BLOCKS:
        if lo <= ch <= hi:
            return (lo, hi)
    return (ch, ch)


def overlaps(band, ch_a, ch_b):
    if ch_a is None or ch_b is None:
        return False
    if band == "2.4":
        return abs(ch_a - ch_b) < 5
    if band == "5":
        return five_block(ch_a) == five_block(ch_b)
    return ch_a == ch_b


def weight(n):
    """How much a neighbouring network matters, based on how loud it is."""
    r = n.get("rssi_dbm")
    if r is None:
        return 0.5
    if r >= -60:
        return 1.0
    if r >= -70:
        return 0.7
    if r >= -80:
        return 0.35
    return 0.1


def congestion(info, neighbors):
    band, ch = info.get("band"), info.get("channel")
    same = [n for n in neighbors if n.get("band") == band and overlaps(band, ch, n.get("channel"))
            and not (n.get("ssid") == info.get("ssid") and n.get("channel") == ch and not n.get("bssid"))]
    score = round(sum(weight(n) for n in same), 2)
    # score every reasonable alternative channel
    if band == "2.4":
        options = [1, 6, 11]
    elif band == "5":
        options = [lo for lo, _ in FIVE_GHZ_BLOCKS[:-1]]
    else:
        options = []
    alt = {}
    for o in options:
        alt[o] = round(sum(weight(n) for n in neighbors if n.get("band") == band
                           and overlaps(band, o, n.get("channel"))), 2)
    return {"overlapping": same, "score": score, "alternatives": alt}


# --------------------------------------------------------------------------- DNS


def dns_query(server, name, timeout=2.0):
    tid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t = time.perf_counter()
        s.sendto(q, (server, 53))
        while True:
            data, _ = s.recvfrom(4096)
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == tid:
                return (time.perf_counter() - t) * 1000
    except OSError:
        return None
    finally:
        s.close()


def system_dns_servers():
    servers = []
    if OS in ("Linux", "Darwin"):
        try:
            with open("/etc/resolv.conf") as f:
                servers += re.findall(r"^\s*nameserver\s+(\d+\.\d+\.\d+\.\d+)", f.read(), re.M)
        except OSError:
            pass
        if OS == "Darwin":
            servers += re.findall(r"nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)", run(["scutil", "--dns"]))
    elif OS == "Windows":
        out = run(["ipconfig", "/all"])
        for m in re.finditer(r"DNS Servers[ .]*:\s*([\d.]+)((?:\s*\n\s+[\d.]+)*)", out):
            servers.append(m.group(1))
            servers += re.findall(r"(\d+\.\d+\.\d+\.\d+)", m.group(2))
    seen, uniq = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq[:3]


def dns_benchmark(gateway):
    targets = {}
    system = system_dns_servers()
    # if the OS only lists a local stub resolver (systemd-resolved, dnsmasq) the router is usually upstream
    local_stub = bool(system) and all(ipaddress.ip_address(s).is_loopback for s in system)
    in_use = set(system) | ({gateway} if gateway and (local_stub or not system) else set())
    if gateway:
        targets[f"Router {gateway}"] = gateway
    for s in system:
        if s != gateway:
            targets[f"System {s}"] = s
    for label, server in PUBLIC_DNS.items():
        if server not in targets.values():
            targets[label] = server
    results = {}
    for label, server in targets.items():
        times, fails = [], 0
        for name in DNS_TEST_NAMES:
            t = dns_query(server, name)
            if t is None:
                fails += 1
            else:
                times.append(t)
        # an uncached lookup shows how fast the resolver is when it has to go out to the internet
        uncached = dns_query(server, f"wd{random.randint(10**6, 10**7)}.example.com", timeout=3)
        results[label] = {"server": server,
                          "median_ms": round(statistics.median(times), 1) if times else None,
                          "max_ms": round(max(times), 1) if times else None,
                          "uncached_ms": round(uncached, 1) if uncached else None,
                          "failures": fails, "queries": len(DNS_TEST_NAMES), "in_use": server in in_use}
    return results


# --------------------------------------------------------------------------- router identification (UPnP / HTTP)


def router_http_info(gw):
    info = {}
    op = lan_opener()
    for scheme in ("http", "https"):
        try:
            r = op.open(urllib.request.Request(f"{scheme}://{gw}/", headers=UA), timeout=4)
            body, headers = r.read(65536).decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            body, headers = e.read(65536).decode("utf-8", "replace") if e.fp else "", e.headers
        except Exception:
            continue
        info["admin_url"] = f"{scheme}://{gw}/"
        if headers.get("Server"):
            info["server_header"] = headers.get("Server")
        realm = re.search(r'realm="([^"]+)"', headers.get("WWW-Authenticate", "") or "")
        if realm:
            info["auth_realm"] = realm.group(1)
        t = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if t and t.group(1).strip():
            info["page_title"] = re.sub(r"\s+", " ", t.group(1)).strip()[:120]
        break
    return info


def ssdp_discover(timeout=3.0):
    locations = {}
    sts = ["urn:schemas-upnp-org:device:InternetGatewayDevice:1",
           "urn:schemas-upnp-org:device:InternetGatewayDevice:2"]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(0.5)
    try:
        for st in sts:
            msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
                   f"MX: 2\r\nST: {st}\r\n\r\n")
            s.sendto(msg.encode(), ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(8192)
            except socket.timeout:
                continue
            m = re.search(r"^location:\s*(\S+)", data.decode("utf-8", "replace"), re.I | re.M)
            if m:
                locations.setdefault(addr[0], m.group(1))
    except OSError:
        pass
    finally:
        s.close()
    return locations


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def soap_call(control_url, service_type, action):
    body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service_type}"/></s:Body></s:Envelope>').encode()
    req = urllib.request.Request(control_url, data=body, headers={
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service_type}#{action}"', **UA})
    try:
        txt = lan_opener().open(req, timeout=4).read(65536).decode("utf-8", "replace")
    except Exception:
        return {}
    return dict(re.findall(r"<(New\w+)>([^<]*)</New\w+>", txt))


def upnp_router(gateway):
    locs = ssdp_discover()
    if not locs:
        return {}
    loc = locs.get(gateway) or next(iter(locs.values()))
    try:
        xml_bytes = lan_opener().open(urllib.request.Request(loc, headers=UA), timeout=4).read(300000)
        root = ET.fromstring(xml_bytes)
    except Exception:
        return {"upnp_enabled": True}
    info = {"upnp_enabled": True}
    for el in root.iter():
        name = _local(el.tag)
        if name in ("friendlyName", "manufacturer", "modelName", "modelNumber") and el.text \
                and name not in info:
            info[name] = el.text.strip()
    base = loc.rsplit("/", 1)[0] if "/" in loc[8:] else loc
    m = re.match(r"(https?://[^/]+)", loc)
    host_base = m.group(1) if m else base
    wan = None
    for svc in root.iter():
        if _local(svc.tag) != "service":
            continue
        fields = {_local(c.tag): (c.text or "").strip() for c in svc}
        if "WANCommonInterfaceConfig" in fields.get("serviceType", ""):
            url = fields.get("controlURL", "")
            url = url if url.startswith("http") else host_base + ("" if url.startswith("/") else "/") + url
            wan = (url, fields["serviceType"])
            break
    if wan:
        props = soap_call(wan[0], wan[1], "GetCommonLinkProperties")
        for k_src, k_dst in (("NewLayer1DownstreamMaxBitRate", "wan_down_bps"),
                             ("NewLayer1UpstreamMaxBitRate", "wan_up_bps")):
            if props.get(k_src, "").isdigit():
                info[k_dst] = int(props[k_src])
        if props.get("NewWANAccessType"):
            info["wan_access_type"] = props["NewWANAccessType"]
        if props.get("NewPhysicalLinkStatus"):
            info["wan_link_status"] = props["NewPhysicalLinkStatus"]
        info["_wan"] = wan
    return info


def wan_background_traffic(wan, seconds=5):
    """Sample the router's total WAN byte counters to see how much the *whole house* is using now."""
    url, stype = wan

    def counters():
        rx = soap_call(url, stype, "GetTotalBytesReceived").get("NewTotalBytesReceived")
        tx = soap_call(url, stype, "GetTotalBytesSent").get("NewTotalBytesSent")
        return (int(rx), int(tx)) if rx and tx and rx.isdigit() and tx.isdigit() else None

    a, t0 = counters(), time.time()
    if not a:
        return None
    time.sleep(seconds)
    b, t1 = counters(), time.time()
    if not b:
        return None

    def delta(x, y):
        d = y - x
        return d + 2 ** 32 if d < 0 else d  # many routers use 32-bit counters

    dt = t1 - t0
    return {"down_mbps": round(delta(a[0], b[0]) * 8 / dt / 1e6, 2),
            "up_mbps": round(delta(a[1], b[1]) * 8 / dt / 1e6, 2)}


# --------------------------------------------------------------------------- devices on the LAN


def parse_arp(text, network=None):
    devices = {}
    for line in text.splitlines():
        ip = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        mac = re.search(r"((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})", line)
        if not ip or not mac:
            continue
        mac_n = ":".join(p.zfill(2) for p in re.split(r"[:-]", mac.group(1).lower()))
        if mac_n in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac_n.startswith("01:00:5e"):
            continue
        try:
            addr = ipaddress.ip_address(ip.group(1))
        except ValueError:
            continue
        if network and addr not in network:
            continue
        if addr.is_multicast or str(addr).endswith(".255"):
            continue
        devices[str(addr)] = {"ip": str(addr), "mac": mac_n,
                              "random_mac": int(mac_n[1], 16) & 0x2 == 0x2}
    return devices


def scan_devices(my_ip):
    net = ipaddress.ip_network(f"{my_ip}/24", strict=False)
    # poke every address so the OS fills its ARP table (harmless empty UDP packet to the discard port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for host in net.hosts():
        try:
            s.sendto(b"", (str(host), 9))
        except OSError:
            pass
    s.close()
    time.sleep(2.5)
    text = run(["arp", "-an"] if OS != "Windows" else ["arp", "-a"])
    if OS == "Linux":
        text += "\n" + run(["ip", "neigh"])
    devs = parse_arp(text, net)
    # reverse DNS (the router usually knows DHCP host names); daemon threads so a slow lookup can't hang us
    def lookup(d):
        try:
            d["name"] = socket.gethostbyaddr(d["ip"])[0]
        except (OSError, UnicodeError):
            pass
    threads = [threading.Thread(target=lookup, args=(d,), daemon=True) for d in devs.values()]
    for t in threads:
        t.start()
    deadline = time.time() + 4
    for t in threads:
        t.join(max(0, deadline - time.time()))
    return sorted(devs.values(), key=lambda d: tuple(int(x) for x in d["ip"].split(".")))


# --------------------------------------------------------------------------- speed test / bufferbloat


class _Counter:
    def __init__(self):
        self.n = 0
        self.lock = threading.Lock()
        self.errors = 0

    def add(self, k):
        with self.lock:
            self.n += k


def _download_worker(ctr, stop):
    while time.time() < stop:
        req = urllib.request.Request(DOWN_URL, headers=UA)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                while time.time() < stop:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    ctr.add(len(chunk))
        except Exception:
            ctr.errors += 1
            time.sleep(0.5)


class _UploadBody:
    def __init__(self, size, ctr, stop):
        self.left, self.ctr, self.stop = size, ctr, stop
        self.block = os.urandom(65536)

    def read(self, n=65536):
        if self.left <= 0:
            return b""
        n = min(n, self.left, len(self.block))
        self.left -= n
        self.ctr.add(n)
        return self.block[:n]


def _upload_worker(ctr, stop):
    size = 4_000_000
    while time.time() < stop:
        req = urllib.request.Request(UP_URL, data=_UploadBody(size, ctr, stop),
                                     headers={"Content-Length": str(size),
                                              "Content-Type": "application/octet-stream", **UA}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=15).read()
        except Exception:
            ctr.errors += 1
            time.sleep(0.5)


def load_test(kind, seconds, streams, ping_host):
    """Run a download or upload test and measure latency while the link is saturated."""
    ctr = _Counter()
    stop = time.time() + seconds
    worker = _download_worker if kind == "download" else _upload_worker
    threads = [threading.Thread(target=worker, args=(ctr, stop), daemon=True) for _ in range(streams)]
    for t in threads:
        t.start()
    loaded = {}

    def pinger():
        time.sleep(2.0)  # let TCP ramp up and fill the buffers first
        n = int((seconds - 3) / (1.0 if OS == "Windows" else 0.2))
        loaded.update(measure_latency(ping_host, count=max(5, n), interval=0.2) or {})

    pt = threading.Thread(target=pinger, daemon=True)
    pt.start()
    samples = []
    while time.time() < stop:
        time.sleep(0.25)
        samples.append((time.time(), ctr.n))
    for t in threads:
        t.join(3)
    pt.join(seconds + 20)
    # throughput measured after a 2 s warm-up so TCP slow start doesn't drag the number down
    warm = [s for s in samples if s[0] >= samples[0][0] + 1.75] if samples else []
    if len(warm) >= 2 and warm[-1][0] > warm[0][0]:
        mbps = (warm[-1][1] - warm[0][1]) * 8 / (warm[-1][0] - warm[0][0]) / 1e6
    else:
        mbps = 0.0
    if ctr.n == 0:
        return {"failed": True, "errors": ctr.errors}
    return {"mbps": round(mbps, 1), "bytes": ctr.n, "errors": ctr.errors, "latency_under_load": loaded}


# --------------------------------------------------------------------------- analysis

SEV_RANK = {"critical": 0, "major": 1, "minor": 2, "info": 3}


def analyze(r, plan_mbps=None):
    F = []

    def add(sev, area, title, why, fix):
        F.append({"severity": sev, "area": area, "title": title, "why": why, "fix": fix})

    w = r.get("wifi") or {}
    neighbors = r.get("neighbors") or []
    gw = r.get("gateway")

    if r.get("vpn_interface"):
        add("major", "This computer", f"Traffic is going through a VPN ({r['vpn_interface']})",
            "A VPN adds latency and usually caps throughput; every result below includes the VPN's overhead.",
            "Disconnect the VPN and run the check again to see your real Wi-Fi/ISP performance.")
    if gw and not is_private(gw):
        add("info", "This computer", f"Default gateway {gw} is not a private address",
            "You may be on a VPN, tethered, or behind an unusual setup, so 'router' results may not be your home router.",
            "Run this on a device connected directly to your home Wi-Fi.")

    if not w:
        add("info", "Wi-Fi", "Could not read Wi-Fi status on this computer",
            "Either you are on Ethernet, the Wi-Fi tools are missing (Linux: install 'iw' / NetworkManager), "
            "or the OS hid the info (macOS/Windows 11 need Location Services permission for the terminal).",
            "Connect over Wi-Fi and allow location access for your terminal, then re-run.")
    else:
        rssi = w.get("rssi_dbm")
        est = " (estimated from %)" if w.get("rssi_estimated") else ""
        if rssi is not None:
            if rssi < -75:
                add("critical", "Wi-Fi signal", f"Very weak signal: {rssi} dBm{est}",
                    "Below about -75 dBm the link drops to very low data rates and retransmits constantly.",
                    "Move closer to the router, raise the router off the floor / out of cabinets, away from "
                    "walls, mirrors, fish tanks and microwaves, or add a mesh node / access point near this room.")
            elif rssi < -67:
                add("major", "Wi-Fi signal", f"Weak signal: {rssi} dBm{est}",
                    "Streaming and video calls need roughly -67 dBm or better for reliable high data rates.",
                    "Reposition the router centrally and high up, or add a mesh node/access point closer to you.")
            elif rssi < -60:
                add("minor", "Wi-Fi signal", f"Fair signal: {rssi} dBm{est}",
                    "Usable, but you are not getting the top data rates your hardware supports.",
                    "Small changes in router placement or antenna orientation can help.")
        noise = w.get("noise_dbm")
        if noise is not None and noise > -85:
            add("major", "Interference", f"High noise floor: {noise} dBm",
                "Non-Wi-Fi interference (microwaves, baby monitors, Bluetooth, cordless phones, USB 3 hubs) "
                "raises the noise floor and reduces the usable signal.",
                "Move the router away from those devices or switch to 5 GHz, which is much less affected.")
        if rssi is not None and noise is not None and rssi - noise < 25:
            add("major", "Interference", f"Low signal-to-noise ratio: {rssi - noise} dB",
                "SNR under ~25 dB forces slow, robust modulation and lots of retransmissions.",
                "Improve signal (closer / mesh) or reduce interference (5 GHz, move router).")

        band = w.get("band")
        same_ssid_5 = [n for n in neighbors if n.get("ssid") and n.get("ssid") == w.get("ssid")
                       and n.get("band") in ("5", "6") and (n.get("rssi_dbm") or -100) > -72]
        if band == "2.4":
            if same_ssid_5:
                add("major", "Wi-Fi band",
                    "Connected on 2.4 GHz even though your router also offers 5 GHz here",
                    "2.4 GHz is slower, more crowded and more prone to interference. Your router's 5 GHz "
                    f"radio is visible at {max(n['rssi_dbm'] for n in same_ssid_5)} dBm.",
                    "Forget and rejoin the network, enable 'band steering' / 'smart connect' on the router, "
                    "or give the 5 GHz band its own name and connect to that.")
            else:
                add("major", "Wi-Fi band", "Connected on the 2.4 GHz band",
                    "2.4 GHz tops out far lower than 5/6 GHz and shares airtime with neighbours, Bluetooth "
                    "and microwaves.",
                    "If your router is dual-band, enable 5 GHz and connect to it (5 GHz has less range, so "
                    "add a mesh node if needed).")
            ch = w.get("channel")
            if ch and ch not in (1, 6, 11):
                add("major", "Wi-Fi channel", f"2.4 GHz channel {ch} is not one of 1/6/11",
                    "Only channels 1, 6 and 11 don't overlap. Anything in between overlaps two of them and "
                    "suffers interference from both.",
                    "Set the router's 2.4 GHz channel to 1, 6 or 11 (see the least-crowded one below).")
            if (w.get("width_mhz") or 0) >= 40:
                add("minor", "Wi-Fi channel", "2.4 GHz is using a 40 MHz wide channel",
                    "In 2.4 GHz a 40 MHz channel overlaps almost the whole band, causing and receiving "
                    "interference; it often ends up slower in practice.",
                    "Set 2.4 GHz channel width to 20 MHz on the router.")
        elif band == "5":
            width = w.get("width_mhz")
            if width and width < 80:
                add("minor", "Wi-Fi channel", f"5 GHz is using a narrow {width} MHz channel",
                    "802.11ac/ax link speed scales with channel width; 80 MHz roughly doubles the 40 MHz rate.",
                    "Set the 5 GHz channel width to 80 MHz (or 'auto 20/40/80') on the router.")

        cg = r.get("congestion") or {}
        if cg.get("overlapping") is not None:
            n_over = len(cg["overlapping"])
            loud = [n for n in cg["overlapping"] if (n.get("rssi_dbm") or -100) >= -70]
            alt = cg.get("alternatives") or {}
            best = min(alt, key=alt.get) if alt else None
            better = best is not None and alt[best] + 0.5 < cg["score"]
            suggestion = (f" Least crowded option right now: channel {best}" +
                          (f"-{five_block(best)[1]} block" if band == "5" else "") + ".") if better else ""
            if cg["score"] >= 3 or len(loud) >= 3:
                add("major", "Channel congestion",
                    f"{n_over} other networks share/overlap your channel ({len(loud)} of them strong)",
                    "Wi-Fi is half-duplex and shared: every network on the same channel takes turns, so "
                    "neighbours' traffic directly eats into your airtime.",
                    "Change the router's channel." + suggestion)
            elif cg["score"] >= 1.5:
                add("minor", "Channel congestion", f"{n_over} other networks overlap your channel",
                    "Some airtime is shared with neighbours.",
                    "Consider changing channel." + suggestion)

        rates = [x for x in (w.get("tx_rate_mbps"), w.get("rx_rate_mbps")) if x]
        if rates:
            link = min(rates)
            if link < 72:
                add("major", "Wi-Fi link", f"Low Wi-Fi link rate: {link:g} Mbps",
                    "The negotiated PHY rate caps real throughput at roughly half of it. This usually "
                    "comes from weak signal, interference, 2.4 GHz, legacy mode or a narrow channel.",
                    "Fix the signal/band/channel issues listed here; real speed will follow the link rate.")
            elif link < 200 and band != "2.4":
                add("minor", "Wi-Fi link", f"Modest Wi-Fi link rate: {link:g} Mbps",
                    "Real-world throughput is roughly 50-65% of the link rate.",
                    "Better signal or a wider channel will raise it.")
        phy = (w.get("phy") or "").lower().strip()
        if "legacy" in phy or re.fullmatch(r"802\.11[abg](/[abg])*", phy):
            add("major", "Wi-Fi standard", f"Connected with an old Wi-Fi standard ({w.get('phy')})",
                "802.11a/b/g is limited to 54 Mbps link rate.",
                "Make sure the router isn't in 'legacy' / 'b/g only' mode and that this device's adapter "
                "and driver support Wi-Fi 5/6.")
        sec = (w.get("security") or "").upper()
        if "WEP" in sec or ("TKIP" in sec and "CCMP" not in sec and "AES" not in sec):
            add("critical", "Wi-Fi security", f"Old security mode in use ({w.get('security')})",
                "WEP and WPA/TKIP force 802.11n/ac/ax devices down to 54 Mbps legacy rates, and are insecure.",
                "Set the router to WPA2-AES (CCMP) or WPA2/WPA3; never 'WPA/TKIP' or 'WPA+WPA2 mixed'.")
        elif re.search(r"\bWPA1\b|(?<![A-Z0-9])WPA[-_ ]PERSONAL|TKIP", sec):
            add("major", "Wi-Fi security", f"Legacy WPA / mixed mode enabled ({w.get('security')})",
                "When old WPA/TKIP is allowed, many routers disable fast 802.11n/ac/ax rates or fall back to "
                "them for some clients. It is also less secure.",
                "Set the router to WPA2-AES only (or WPA2/WPA3), not 'WPA/WPA2 mixed' or 'TKIP+AES'.")
        if w.get("power_save"):
            add("minor", "This computer", "Wi-Fi power saving is ON",
                "Power saving makes the adapter sleep between beacons, adding latency spikes and jitter.",
                "Linux: `sudo iw dev %s set power_save off` (persist via NetworkManager "
                "wifi.powersave = 2)." % w.get("iface", "wlan0"))

    lat_r = r.get("latency_router")
    lat_i = r.get("latency_internet") or {}
    if lat_r and lat_r.get("received"):
        if lat_r["loss_pct"] >= 2:
            add("critical" if lat_r["loss_pct"] >= 5 else "major", "Wi-Fi link",
                f"{lat_r['loss_pct']}% packet loss to your own router",
                "Loss on the very first hop is a Wi-Fi problem (signal, interference or an overloaded router), "
                "not your ISP. Lost packets cause stalls, buffering and dropped calls.",
                "Improve signal/channel as above; reboot the router; if it persists the router may be failing.")
        if lat_r.get("avg", 0) > 20 or lat_r.get("p95", 0) > 50:
            add("major", "Wi-Fi link",
                f"High latency to your router: avg {lat_r['avg']} ms, p95 {lat_r['p95']} ms",
                "A healthy Wi-Fi hop is 1-5 ms. High values mean airtime contention, interference, "
                "power saving, or a router CPU that is overloaded.",
                "Check channel congestion and power saving; reboot the router; if it stays high, consider "
                "a newer router.")
        elif lat_r.get("jitter", 0) > 10:
            add("minor", "Wi-Fi link", f"Jittery Wi-Fi hop: jitter {lat_r['jitter']} ms",
                "Jitter on the first hop hurts calls and games even when speed looks fine.",
                "Usually congestion or power saving; see the related items.")
    elif lat_r and gw:
        add("info", "Router", "Router does not answer ping",
            "Some routers ignore ping; the router hop could not be timed directly.", "Nothing to do.")

    if lat_i.get("received"):
        rt = lat_r.get("avg", 0) if lat_r and lat_r.get("received") else 0
        isp = lat_i["avg"] - rt
        if lat_i["loss_pct"] >= 2 and not (lat_r and lat_r.get("loss_pct", 0) >= 2):
            add("major", "Internet / ISP", f"{lat_i['loss_pct']}% packet loss to the internet "
                "(but not to your router)",
                "The loss is beyond your Wi-Fi: in the modem, the line, or at your ISP.",
                "Power-cycle the modem; check cables/line; if it continues, contact your ISP with these numbers.")
        if isp > 60:
            add("major", "Internet / ISP", f"High internet latency beyond your router: ~{isp:.0f} ms",
                "Typical fixed broadband adds 5-30 ms to a nearby Cloudflare/Google server.",
                "Power-cycle the modem. If it stays high, it's your ISP line/route (or a VPN).")
    elif r.get("latency_internet") is not None:
        add("critical", "Internet / ISP", "Could not reach the internet test hosts",
            "No replies from 1.1.1.1 / 8.8.8.8.", "Check that the internet connection is up.")

    lt = r.get("load_test") or {}
    idle = (lt.get("idle") or {}).get("median") or lat_i.get("median")
    for kind in ("download", "upload"):
        t = lt.get(kind)
        if not t or not idle or t.get("failed"):
            continue
        lul = t.get("latency_under_load") or {}
        if lul.get("median") is not None:
            extra = lul["median"] - idle
            t["bloat_ms"] = round(extra, 1)
            if extra > 100:
                add("critical", "Bufferbloat", f"Latency jumps by +{extra:.0f} ms during {kind}s",
                    "Your router/modem buffers too much data when the line is busy, so any download/upload "
                    "(updates, cloud backup, streaming) makes everything else in the house laggy.",
                    "Enable SQM / Smart Queue Management / 'Adaptive QoS' (fq_codel or CAKE) on the router, "
                    "set to ~90% of your measured speeds. If your router can't, OpenWrt or a newer router can.")
            elif extra > 30:
                add("major", "Bufferbloat", f"Latency rises by +{extra:.0f} ms during {kind}s",
                    "Moderate bufferbloat: calls and games get laggy when someone downloads or uploads.",
                    "Turn on SQM / Smart Queue / Adaptive QoS on the router.")
        elif lul.get("loss_pct") == 100:
            add("major", "Bufferbloat", f"Pings were dropped entirely during the {kind} test",
                "The line is so saturated that latency-sensitive traffic is lost.",
                "Enable SQM / Smart Queue / Adaptive QoS on the router.")

    if any((lt.get(k) or {}).get("failed") for k in ("download", "upload")):
        add("info", "Speed", "Speed test could not reach speed.cloudflare.com",
            "A firewall, proxy or content filter blocked it, so speed and bufferbloat were not measured.",
            "Run a test at https://speed.cloudflare.com or https://www.waveform.com/tools/bufferbloat instead.")
    dl = (lt.get("download") or {}).get("mbps")
    ul = (lt.get("upload") or {}).get("mbps")
    rates = [x for x in (w.get("tx_rate_mbps"), w.get("rx_rate_mbps")) if x]
    link = min(rates) if rates else None
    if dl:
        if plan_mbps:
            if dl < 0.7 * plan_mbps:
                if link and link * 0.6 < plan_mbps:
                    add("major", "Speed", f"Download {dl:g} Mbps vs {plan_mbps:g} Mbps plan - the Wi-Fi link is "
                        "the bottleneck",
                        f"Your Wi-Fi link rate ({link:g} Mbps) can't carry your plan speed; real throughput "
                        "is ~60% of link rate.",
                        "Fix the signal/band/width items above, or use Ethernet / a Wi-Fi 6 adapter for this device.")
                else:
                    add("major", "Speed", f"Download {dl:g} Mbps is well below your {plan_mbps:g} Mbps plan",
                        "Your Wi-Fi link has headroom, so the loss is elsewhere: other devices using bandwidth, "
                        "router CPU limits, the modem, or the ISP.",
                        "Test on Ethernet next to the router. If that's also slow, call your ISP; if it's fast, "
                        "look at the congestion/bufferbloat/background-traffic items.")
        elif link and dl < 0.25 * link and dl < 200:
            add("minor", "Speed", f"Download {dl:g} Mbps is low compared with your {link:g} Mbps Wi-Fi link",
                "The radio link isn't the limit, so the bottleneck is likely your ISP plan, other devices, "
                "or the router/modem.",
                "Re-run with --plan <your plan Mbps> for a clearer verdict, and compare with an Ethernet test.")

    bg = r.get("background_traffic")
    if bg:
        if bg["down_mbps"] > 5 or bg["up_mbps"] > 2:
            add("major", "Other devices",
                f"Other devices are already using {bg['down_mbps']} Mbps down / {bg['up_mbps']} Mbps up",
                "Measured from the router's WAN counters before the speed test: something in the house "
                "(streaming, game/OS updates, cloud backup, torrents, cameras) is consuming bandwidth.",
                "Check the router's traffic/client page to see which device; schedule backups/updates at night; "
                "enable QoS/SQM so background transfers don't hurt everyone else.")

    dns = r.get("dns") or {}
    pub = [v["median_ms"] for k, v in dns.items() if k in PUBLIC_DNS and v.get("median_ms")]
    for label, v in dns.items():
        if not v.get("in_use"):
            continue
        if v.get("failures", 0) >= 2:
            add("major", "DNS", f"{label} failed {v['failures']}/{v['queries']} lookups",
                "Failed DNS lookups make pages hang for seconds before loading.",
                "Set DNS on the router (or this device) to 1.1.1.1 / 8.8.8.8 / 9.9.9.9.")
        elif v.get("median_ms") and pub and v["median_ms"] > 60 and v["median_ms"] > 2 * min(pub):
            add("minor", "DNS", f"{label} is slow: {v['median_ms']} ms vs {min(pub)} ms for the fastest public DNS",
                "Every new website or app connection waits for DNS first; slow DNS makes browsing feel sluggish.",
                f"Switch DNS to the fastest public resolver measured here.")

    devs = r.get("devices")
    if devs and len(devs) > 25:
        add("minor", "Other devices", f"{len(devs)} devices are active on your network",
            "Every Wi-Fi device takes airtime; older/slow devices (2.4 GHz IoT, old phones) use it inefficiently.",
            "Move IoT gear to a separate 2.4 GHz network, remove devices you don't use, consider a mesh/Wi-Fi 6 router.")

    up = r.get("router") or {}
    if up.get("upnp_enabled"):
        add("info", "Router", "UPnP is enabled on the router",
            "Not a speed issue, but UPnP lets any device open ports. Useful for consoles; a security trade-off.",
            "Disable it if you don't need it.")

    F.sort(key=lambda f: SEV_RANK[f["severity"]])
    return F


# --------------------------------------------------------------------------- report


def fmt_lat(x):
    if not x or not x.get("received"):
        return "no replies" if x else "n/a"
    return (f"avg {x['avg']} ms, median {x['median']}, p95 {x['p95']}, jitter {x['jitter']}, "
            f"loss {x['loss_pct']}% [{x.get('method')}]")


def build_report(r, findings):
    L = []
    L.append(f"# Wi-Fi Doctor report - {r['time']}")
    L.append("")
    L.append(f"Computer: {r['os']}  |  local IP {r.get('local_ip')}  |  router/gateway {r.get('gateway')} "
             f"(via {r.get('gateway_iface')})")
    L.append("")
    sev_icon = {"critical": "[CRITICAL]", "major": "[MAJOR]", "minor": "[minor]", "info": "[info]"}
    problems = [f for f in findings if f["severity"] != "info"]
    L.append("## What is slowing your Wi-Fi down (worst first)")
    L.append("")
    if not problems:
        L.append("Nothing significant found. Your Wi-Fi looks healthy from this spot.")
    for i, f in enumerate(problems, 1):
        L.append(f"{i}. {sev_icon[f['severity']]} **{f['title']}** ({f['area']})")
        L.append(f"   - Why it matters: {f['why']}")
        L.append(f"   - Fix: {f['fix']}")
    notes = [f for f in findings if f["severity"] == "info"]
    if notes:
        L.append("")
        L.append("Notes:")
        for f in notes:
            L.append(f"- {f['title']}: {f['why']} {f['fix']}")
    L.append("")

    w = r.get("wifi") or {}
    L.append("## Wi-Fi connection")
    if w:
        fields = [("Interface", "iface"), ("Network (SSID)", "ssid"), ("BSSID", "bssid"), ("Band (GHz)", "band"),
                  ("Channel", "channel"), ("Channel width (MHz)", "width_mhz"), ("Signal (dBm)", "rssi_dbm"),
                  ("Noise (dBm)", "noise_dbm"), ("Signal quality (%)", "signal_pct"),
                  ("Link rate TX (Mbps)", "tx_rate_mbps"), ("Link rate RX (Mbps)", "rx_rate_mbps"),
                  ("Standard", "phy"), ("Security", "security"), ("Power saving", "power_save")]
        for label, k in fields:
            if w.get(k) not in (None, ""):
                L.append(f"- {label}: {w[k]}")
    else:
        L.append("- not available")
    L.append("")

    cg = r.get("congestion")
    nb = r.get("neighbors") or []
    L.append(f"## Nearby networks ({len(nb)} seen)")
    if cg:
        L.append(f"- Networks overlapping your channel: {len(cg['overlapping'])} (congestion score {cg['score']})")
        if cg["alternatives"]:
            L.append("- Congestion score per channel (lower is better): " +
                     ", ".join(f"ch {k}: {v}" for k, v in sorted(cg["alternatives"].items())))
    by_ch = {}
    for n in nb:
        if n.get("channel"):
            by_ch.setdefault((n.get("band"), n["channel"]), []).append(n)
    for (band, ch), ns in sorted(by_ch.items(), key=lambda x: (str(x[0][0]), x[0][1])):
        L.append(f"- {band} GHz ch {ch}: {len(ns)} network(s), strongest "
                 f"{max((n.get('rssi_dbm') or -100) for n in ns)} dBm")
    L.append("")

    L.append("## Latency")
    L.append(f"- To router ({r.get('gateway')}): {fmt_lat(r.get('latency_router'))}")
    L.append(f"- To internet (1.1.1.1): {fmt_lat(r.get('latency_internet'))}")
    if r.get("latency_internet_2"):
        L.append(f"- To internet (8.8.8.8): {fmt_lat(r.get('latency_internet_2'))}")
    L.append("")

    lt = r.get("load_test")
    if lt:
        L.append("## Speed and bufferbloat (speed.cloudflare.com)")
        L.append(f"- Idle latency: {fmt_lat(lt.get('idle'))}")
        for kind in ("download", "upload"):
            t = lt.get(kind)
            if t and t.get("failed"):
                L.append(f"- {kind.capitalize()}: failed (could not reach the test server)")
            elif t:
                L.append(f"- {kind.capitalize()}: {t['mbps']} Mbps; latency while loaded: "
                         f"{fmt_lat(t.get('latency_under_load'))}"
                         + (f" -> +{t['bloat_ms']} ms" if t.get("bloat_ms") is not None else ""))
        L.append("")

    if r.get("background_traffic"):
        bg = r["background_traffic"]
        L.append("## Whole-house traffic before the test (router WAN counters)")
        L.append(f"- {bg['down_mbps']} Mbps down / {bg['up_mbps']} Mbps up")
        L.append("")

    if r.get("dns"):
        L.append("## DNS lookup times")
        for label, v in r["dns"].items():
            if v["failures"] == v["queries"] and not v.get("in_use"):
                L.append(f"- {label}: does not answer DNS (not used by this device)")
                continue
            L.append(f"- {label}: median {v['median_ms']} ms, uncached {v['uncached_ms']} ms, "
                     f"failures {v['failures']}/{v['queries']}" + ("  <- used by this device" if v.get("in_use") else ""))
        L.append("")

    rt = {k: v for k, v in (r.get("router") or {}).items() if not k.startswith("_")}
    if rt:
        L.append("## Router")
        for k, v in rt.items():
            if k in ("wan_down_bps", "wan_up_bps"):
                v = f"{v / 1e6:g} Mbps"
            L.append(f"- {k}: {v}")
        L.append("")

    devs = r.get("devices")
    if devs is not None:
        L.append(f"## Devices on your network ({len(devs)} found)")
        for d in devs:
            tag = " (randomized/private MAC - usually a phone or laptop)" if d["random_mac"] else ""
            L.append(f"- {d['ip']}  {d['mac']}  {d.get('name', '')}{tag}")
        L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description="Find what's slowing down your Wi-Fi.")
    ap.add_argument("--quick", action="store_true", help="skip the speed and bufferbloat tests")
    ap.add_argument("--plan", type=float, metavar="MBPS", help="your ISP plan's download speed in Mbps")
    ap.add_argument("--duration", type=int, default=10, help="seconds per speed test direction (default 10)")
    ap.add_argument("--no-devices", action="store_true", help="don't list devices on the network")
    ap.add_argument("--iface", help="Wi-Fi interface to inspect (Linux only)")
    ap.add_argument("--out", default="wifi_report.md", help="where to write the Markdown report")
    ap.add_argument("--json", metavar="PATH", help="also write raw results as JSON")
    a = ap.parse_args()

    print("Wi-Fi Doctor - checking what slows down your Wi-Fi\n", flush=True)
    r = {"time": datetime.now().strftime("%Y-%m-%d %H:%M"), "os": f"{OS} {platform.release()}"}

    log("Finding your router...")
    gw, gw_iface = default_gateway()
    r["gateway"], r["gateway_iface"] = gw, gw_iface
    r["local_ip"] = local_ip()
    if gw_iface and re.match(r"^(tun|tap|wg|utun|ppp|ipsec|tailscale|zt|nordlynx|proton)", str(gw_iface)):
        r["vpn_interface"] = gw_iface

    log("Reading this computer's Wi-Fi connection and scanning nearby networks...")
    info, neighbors = wifi_status(a.iface or gw_iface)
    r["wifi"], r["neighbors"] = info, neighbors
    if info and info.get("channel"):
        r["congestion"] = congestion(info, neighbors)

    log("Measuring latency to the router and to the internet...")
    res = {}

    def job(key, host, port):
        res[key] = measure_latency(host, count=30, interval=0.2, tcp_port=port)

    jobs = [("latency_internet", PUBLIC_HOSTS[0], 443), ("latency_internet_2", PUBLIC_HOSTS[1], 443)]
    if gw:
        jobs.insert(0, ("latency_router", gw, 80))
    ts = [threading.Thread(target=job, args=j, daemon=True) for j in jobs]
    for t in ts:
        t.start()
    for t in ts:
        t.join(120)
    r.update(res)

    if gw and is_private(gw):
        log("Identifying the router (UPnP / web page)...")
        router = {}
        try:
            router.update(router_http_info(gw))
            router.update(upnp_router(gw))
        except Exception as e:
            log(f"router probe failed: {e}")
        r["router"] = router
        if router.get("_wan"):
            log("Sampling whole-house traffic from the router for 5 s...")
            r["background_traffic"] = wan_background_traffic(router["_wan"])

    log("Timing DNS lookups...")
    r["dns"] = dns_benchmark(gw if gw and is_private(gw) else None)

    if not a.quick:
        log("Measuring idle latency...")
        lt = {"idle": measure_latency(PUBLIC_HOSTS[0], count=20, interval=0.2)}
        log(f"Download test ({a.duration}s) while measuring latency under load...")
        lt["download"] = load_test("download", a.duration, 4, PUBLIC_HOSTS[0])
        log(f"Upload test ({a.duration}s) while measuring latency under load...")
        lt["upload"] = load_test("upload", a.duration, 3, PUBLIC_HOSTS[0])
        r["load_test"] = lt

    if not a.no_devices and r.get("local_ip") and is_private(r["local_ip"]):
        log("Listing devices on your network...")
        r["devices"] = scan_devices(r["local_ip"])

    findings = analyze(r, a.plan)
    r["findings"] = findings
    report = build_report(r, findings)
    print("\n" + report)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"\nReport saved to {os.path.abspath(a.out)}")
    if a.json:
        clean = dict(r)
        if clean.get("router"):
            clean["router"] = {k: v for k, v in clean["router"].items() if not k.startswith("_")}
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2, default=str)
        print(f"Raw data saved to {os.path.abspath(a.json)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
