import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import wifi_doctor as wd  # noqa: E402

IW_LINK = """Connected to aa:bb:cc:dd:ee:ff (on wlan0)
\tSSID: HomeNet
\tfreq: 2437
\tRX: 123456 bytes (789 packets)
\tTX: 23456 bytes (123 packets)
\tsignal: -71 dBm
\trx bitrate: 65.0 MBit/s MCS 7
\ttx bitrate: 52.0 MBit/s MCS 5
"""
IW_INFO = """Interface wlan0
\tifindex 3
\ttype managed
\twiphy 0
\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
\ttxpower 22.00 dBm
"""
NMCLI = "\n".join([
    "*:HomeNet:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:2437 MHz:65 Mbit/s:58:WPA2",
    ":HomeNet:AA\\:BB\\:CC\\:DD\\:EE\\:00:44:5220 MHz:540 Mbit/s:70:WPA2",
    ":Neighbor1:11\\:11\\:11\\:11\\:11\\:11:6:2437 MHz:130 Mbit/s:80:WPA2",
    ":Neighbor2:22\\:22\\:22\\:22\\:22\\:22:5:2432 MHz:130 Mbit/s:75:WPA2",
    ":Neighbor3:33\\:33\\:33\\:33\\:33\\:33:8:2447 MHz:130 Mbit/s:70:WPA1 WPA2",
    ":Far:44\\:44\\:44\\:44\\:44\\:44:11:2462 MHz:130 Mbit/s:20:WPA2",
])
NETSH_IF = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : 11:22:33:44:55:66
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Band                   : 5 GHz
    Channel                : 36
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 960.5
    Signal                 : 90%
    Rssi                   : -48
    Profile                : HomeNet
"""
NETSH_NETS = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 90%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 36
    BSSID 2                 : 11:22:33:44:55:67
         Signal             : 99%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 : Cafe
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 99:88:77:66:55:44
         Signal             : 60%
         Radio type         : 802.11ac
         Channel            : 40
"""
MAC_JSON = {"SPAirPortDataType": [{"spairport_airport_interfaces": [{
    "_name": "en0",
    "spairport_current_network_information": {
        "_name": "HomeNet", "spairport_network_channel": "149 (5GHz, 40MHz)",
        "spairport_network_phymode": "802.11ac", "spairport_network_rate": 400,
        "spairport_security_mode": "spairport_security_mode_wpa2_personal",
        "spairport_signal_noise": "-58 dBm / -82 dBm"},
    "spairport_airport_other_local_wireless_networks": [
        {"_name": "N1", "spairport_network_channel": "153 (5GHz, 80MHz)", "spairport_signal_noise": "-62 dBm / -92 dBm"},
        {"_name": "N2", "spairport_network_channel": "6 (2GHz, 20MHz)", "spairport_signal_noise": "-50 dBm / -92 dBm"},
    ]}]}]}

PING_LINUX = """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.31 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=45.2 ms
64 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=3.10 ms

--- 192.168.1.1 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 3004ms
rtt min/avg/max/mdev = 2.310/16.870/45.200/20.0 ms
"""
PING_WIN = """Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=14ms TTL=57
Reply from 1.1.1.1: bytes=32 time<1ms TTL=57
Request timed out.

Ping statistics for 1.1.1.1:
    Packets: Sent = 3, Received = 2, Lost = 1 (33% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 14ms, Average = 7ms
"""
ARP_MAC = """? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
? (192.168.1.23) at 3a:1:2:3:4:5 on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""
ARP_WIN = """Interface: 192.168.1.10 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
ROUTE_WIN = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.10     35
          0.0.0.0          0.0.0.0         10.8.0.1         10.8.0.5     50
"""
PROC_ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
"""


class Parsers(unittest.TestCase):
    def test_iw(self):
        link = wd.parse_iw_link(IW_LINK)
        self.assertEqual(link["ssid"], "HomeNet")
        self.assertEqual((link["channel"], link["band"]), (6, "2.4"))
        self.assertEqual(link["rssi_dbm"], -71)
        self.assertEqual(link["tx_rate_mbps"], 52.0)
        self.assertIn("802.11n", link["phy"])
        info = wd.parse_iw_info(IW_INFO)
        self.assertEqual((info["channel"], info["width_mhz"], info["band"]), (6, 20, "2.4"))

    def test_nmcli(self):
        cur, nb = wd.parse_nmcli(NMCLI)
        self.assertEqual(cur["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(cur["channel"], 6)
        self.assertEqual(len(nb), 5)
        self.assertEqual(nb[0]["band"], "5")

    def test_netsh(self):
        info = wd.parse_netsh_interfaces(NETSH_IF)
        self.assertEqual(info["ssid"], "HomeNet")
        self.assertEqual((info["channel"], info["band"], info["rssi_dbm"]), (36, "5", -48))
        self.assertEqual(info["tx_rate_mbps"], 960.5)
        nets = wd.parse_netsh_networks(NETSH_NETS)
        self.assertEqual(len(nets), 3)
        self.assertEqual(nets[1]["band"], "2.4")
        self.assertEqual(nets[2]["band"], "5")
        self.assertEqual(nets[2]["ssid"], "Cafe")

    def test_macos(self):
        info, nb = wd.parse_macos_profiler(MAC_JSON)
        self.assertEqual((info["channel"], info["band"], info["width_mhz"]), (149, "5", 40))
        self.assertEqual((info["rssi_dbm"], info["noise_dbm"]), (-58, -82))
        self.assertEqual(nb[1]["band"], "2.4")

    def test_ping(self):
        self.assertEqual(wd.parse_ping(PING_LINUX), [2.31, 45.2, 3.10])
        self.assertEqual(wd.parse_ping(PING_WIN), [14.0, 0.5])
        s = wd.summarize(wd.parse_ping(PING_LINUX), 4)
        self.assertEqual(s["loss_pct"], 25.0)

    def test_arp(self):
        import ipaddress
        net = ipaddress.ip_network("192.168.1.0/24")
        d = wd.parse_arp(ARP_MAC, net)
        self.assertEqual(sorted(d), ["192.168.1.1", "192.168.1.23"])
        self.assertEqual(d["192.168.1.1"]["mac"], "00:11:22:33:44:55")
        self.assertTrue(d["192.168.1.23"]["random_mac"])
        self.assertEqual(list(wd.parse_arp(ARP_WIN, net)), ["192.168.1.1"])

    def test_routes(self):
        self.assertEqual(wd.parse_windows_route(ROUTE_WIN), ("192.168.1.1", "192.168.1.10"))
        self.assertEqual(wd.parse_proc_net_route(PROC_ROUTE), ("192.168.1.1", "wlan0"))


class Analysis(unittest.TestCase):
    def test_bad_24ghz_network(self):
        info = {**wd.parse_iw_info(IW_INFO), **wd.parse_iw_link(IW_LINK), "power_save": True}
        _, nb = wd.parse_nmcli(NMCLI)
        r = {"gateway": "192.168.1.1", "wifi": info, "neighbors": nb,
             "congestion": wd.congestion(info, nb),
             "latency_router": {"sent": 30, "received": 28, "loss_pct": 6.7, "avg": 25, "median": 8,
                                "p95": 80, "jitter": 15},
             "latency_internet": {"sent": 30, "received": 30, "loss_pct": 0, "avg": 40, "median": 30,
                                  "p95": 90, "jitter": 10},
             "load_test": {"idle": {"median": 30},
                           "download": {"mbps": 20, "latency_under_load": {"median": 250}},
                           "upload": {"mbps": 5, "latency_under_load": {"median": 70}}},
             "background_traffic": {"down_mbps": 12.0, "up_mbps": 0.5},
             "dns": {"Router 192.168.1.1": {"median_ms": 150, "failures": 0, "queries": 8},
                     "Cloudflare 1.1.1.1": {"median_ms": 12, "failures": 0, "queries": 8}}}
        r["dns"]["Router 192.168.1.1"]["in_use"] = True
        titles = " | ".join(f["title"] for f in wd.analyze(r, plan_mbps=300))
        for expect in ("Weak signal", "2.4 GHz even though", "packet loss to your own router",
                       "High latency to your router", "Latency jumps", "Latency rises", "Wi-Fi link is",
                       "Other devices are already using", "Router 192.168.1.1 is slow", "power saving",
                       "share/overlap your channel"):
            self.assertIn(expect, titles)
        self.assertEqual(wd.analyze(r)[0]["severity"], "critical")

    def test_healthy(self):
        info = wd.parse_netsh_interfaces(NETSH_IF)
        info["width_mhz"] = 80
        r = {"gateway": "192.168.1.1", "wifi": info, "neighbors": [], "congestion": wd.congestion(info, []),
             "latency_router": {"sent": 30, "received": 30, "loss_pct": 0, "avg": 2, "median": 2, "p95": 4,
                                "jitter": 1},
             "latency_internet": {"sent": 30, "received": 30, "loss_pct": 0, "avg": 12, "median": 12,
                                  "p95": 15, "jitter": 1}}
        problems = [f for f in wd.analyze(r) if f["severity"] != "info"]
        self.assertEqual(problems, [])

    def test_tkip(self):
        r = {"wifi": {"security": "WPA-Personal TKIP", "band": "5"}}
        self.assertEqual(wd.analyze(r)[0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
