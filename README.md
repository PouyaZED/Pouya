# Wi-Fi Doctor

Finds what is slowing down your Wi-Fi and tells you how to fix it, ranked worst-first.

## Run it

On a laptop or desktop **connected to the Wi-Fi you want to check** (Python 3.8+, nothing to install):

```bash
python3 wifi_doctor.py               # full check, ~1-2 minutes
python3 wifi_doctor.py --plan 500    # tell it your ISP plan (Mbps) for a sharper verdict
python3 wifi_doctor.py --quick       # skip the speed/bufferbloat test
```

Windows: `py wifi_doctor.py`. The report is printed and saved to `wifi_report.md`
(`--json results.json` also saves the raw numbers).

Tips for accurate results
- Sit where the Wi-Fi is usually slow.
- Turn off any VPN.
- macOS 14+ / Windows 11: allow **Location Services** for Terminal / PowerShell, otherwise the OS
  hides the Wi-Fi channel and nearby networks.
- Linux: needs `iw` and/or NetworkManager (`nmcli`), which most desktops already have.

## What it checks

| Area | What it looks at | Typical culprit it catches |
|---|---|---|
| Signal | RSSI (dBm), noise, SNR | router too far / behind walls, interference |
| Band | 2.4 vs 5/6 GHz, whether your router's 5 GHz is visible | stuck on 2.4 GHz |
| Channel | channel, width, overlap with neighbours, least crowded alternative | crowded channel, 2.4 GHz on ch 3/8, 20/40 MHz on 5 GHz |
| Link | negotiated link rate, Wi-Fi standard | legacy b/g mode, low PHY rate |
| Security | WEP / WPA-TKIP / mixed mode | TKIP capping you at 54 Mbps |
| First hop | latency, jitter, loss to the router | Wi-Fi problems vs ISP problems |
| Internet | latency/loss to 1.1.1.1 and 8.8.8.8 | modem / ISP issues |
| Speed + bufferbloat | download/upload with latency under load (speed.cloudflare.com) | missing SQM/QoS |
| Other devices | router WAN counters via UPnP, device list (ARP) | someone else streaming / backing up |
| DNS | lookups via your resolvers vs 1.1.1.1 / 8.8.8.8 / 9.9.9.9 | slow or failing router DNS |
| This computer | VPN, Wi-Fi power saving | latency spikes |

It only reads information. It never logs in to the router or changes any settings.

## Tests

```bash
python3 -m unittest discover -s tests
```
