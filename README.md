# NOIR // PACKET ANALYZER

> A dark-themed network packet analyzer with live capture, PCAP analysis, threat detection, and HTML report export.

![Python](https://img.shields.io/badge/Python-3.8+-00d4ff?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-ff3366?style=flat-square&logo=flask&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.x-39ff14?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-b967ff?style=flat-square)

---

## Features

- **Live Capture** — real-time packet sniffing via Scapy with auto-scroll
- **PCAP Analysis** — upload and analyze `.pcap` / `.pcapng` files
- **Threat Detection**
  - Plaintext credential extraction (POST bodies, Basic Auth)
  - Known malicious IP flagging
  - Suspicious port detection (4444, 1337, 31337, etc.)
  - External traffic identification
- **Protocol Classification** — HTTP, DNS, TCP, UDP with color-coded display
- **Packet Detail View** — click any row for full breakdown
- **Filtering & Search** — filter by protocol, severity, or free-text search
- **HTML Report Export** — downloadable forensic report with critical findings summary

---

## Installation

```bash
git clone https://github.com/Radhesh-Mutreja/noir-packet-analyzer
cd noir-packet-analyzer
pip install -r requirements.txt
```

### Run

```bash
# Linux/Mac — requires root for live capture
sudo python app.py

# Windows — run as Administrator
python app.py
```

Open `http://localhost:5000` in your browser.

---

## Usage

### Live Capture
1. Enter your network interface (e.g. `eth0`, `wlan0`) — leave blank to auto-detect
2. Click **START CAPTURE**
3. Packets stream in real-time, critical findings highlighted immediately
4. Click **STOP CAPTURE** when done

### PCAP Analysis
1. Click the **DROP PCAP FILE** zone
2. Select your `.pcap` or `.pcapng` file
3. Results load instantly (capped at 500 packets for performance)

### Export Report
- Click **EXPORT HTML REPORT** at any time to download a full forensic report

---

## Detection Rules

| Flag | Trigger | Severity |
|------|---------|----------|
| `PLAINTEXT_CREDS` | password/user fields in HTTP body or Basic Auth header | Critical |
| `KNOWN_MALICIOUS_IP` | IP matches local threat intel list | Critical |
| `SUSPICIOUS_PORT_*` | Traffic on ports: 4444, 1337, 31337, 3389, 23 etc. | Warning |
| `EXTERNAL_TRAFFIC` | Destination is a public IP | Info |
| `DNS_QUERY` | DNS resolution detected | Info |
| `HTTP_REQUEST` | Outbound HTTP detected | Info |

---

## Extending Threat Intel

Edit `KNOWN_BAD_IPS` in `app.py` to add your own indicators. You can also integrate AbuseIPDB or any threat feed by replacing the local set with an API call.

---

## Stack

- **Backend** — Python 3, Flask, Scapy
- **Frontend** — Vanilla JS, CSS variables, Google Fonts (Orbitron, Share Tech Mono, Rajdhani)
- **No external JS frameworks** — fully self-contained

---

## Part of the Noir Toolkit

| Tool | Description |
|------|-------------|
| [Noir IDS](https://github.com/Radhesh-Mutreja/noir-ids) | Intrusion detection via system/auth log monitoring |
| [ReconX](https://github.com/Radhesh-Mutreja/ReconX) | OSINT framework with 6 concurrent recon modules |
| [NETRUNNER](https://github.com/Radhesh-Mutreja/netrunner) | Network toolkit with cyberpunk UI |
| [D0RKER](https://github.com/Radhesh-Mutreja/d0rker) | Google dorking GUI for OSINT research |
| **Noir Packet Analyzer** | You are here |

---

## Disclaimer

This tool is intended for **educational purposes and authorized network analysis only**. Do not use on networks you do not own or have explicit permission to test. The developer is not responsible for misuse.

---

## Author

**Radhesh Mutreja** — MSc DFIS, National Forensic Sciences University  
GitHub: [@nullRdx](https://github.com/Radhesh-Mutreja) | LinkedIn: [radhesh-mutreja](https://linkedin.com/in/radhesh-mutreja-210714271/)
