# WiFi Penetration Testing MCP Server

> ⚠️ **FOR AUTHORIZED SECURITY TESTING ONLY**
> All operations must be performed on networks you own or have **explicit written permission** to test.
> Unauthorized access to computer networks is illegal under the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and similar laws worldwide.

---

## Overview

This MCP server wraps the **aircrack-ng suite** (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng) into a structured AI-accessible toolkit for wireless penetration testing and security audits.

---

## Requirements

| Requirement       | Details                                      |
|-------------------|----------------------------------------------|
| OS                | Linux (Kali, Parrot, Ubuntu)                 |
| Python            | 3.10+                                        |
| Privileges        | Must run as **root** (`sudo`)                |
| WiFi adapter      | Must support **monitor mode & packet injection** |
| aircrack-ng suite | `sudo apt install aircrack-ng`               |

### Install aircrack-ng

```bash
sudo apt update && sudo apt install -y aircrack-ng
```

### Optional (recommended)

```bash
sudo apt install -y tshark   # for handshake detection in capture files
sudo apt install -y hashcat  # for GPU-accelerated cracking (outside this MCP)
```

---

## Installation

```bash
# Clone or copy the server files
cd wifi_pentest_mcp

# Install Python dependencies
pip install -r requirements.txt

# Run as root
sudo python server.py
```

---

## Claude Desktop / MCP Client Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wifi_pentest": {
      "command": "sudo",
      "args": ["python", "/path/to/wifi_pentest_mcp/server.py"]
    }
  }
}
```

Or using `uv`:

```json
{
  "mcpServers": {
    "wifi_pentest": {
      "command": "sudo",
      "args": ["uv", "run", "/path/to/wifi_pentest_mcp/server.py"]
    }
  }
}
```

---

## Available Tools

### 🔧 Setup & Diagnostics

| Tool | Description |
|------|-------------|
| `wifi_check_tools` | Verify aircrack-ng suite is installed; list interfaces |
| `wifi_list_interfaces` | List wireless interfaces with chipset/driver info |
| `wifi_kill_interfering_processes` | Kill NetworkManager, wpa_supplicant (optional dry-run) |

### 📡 Monitor Mode

| Tool | Description |
|------|-------------|
| `wifi_enable_monitor_mode` | `airmon-ng start <iface>` — puts card into monitor mode |
| `wifi_disable_monitor_mode` | `airmon-ng stop <iface>` — restores managed mode |

### 🔍 Scanning & Capture

| Tool | Description |
|------|-------------|
| `wifi_scan_networks` | Passive scan for APs & clients via airodump-ng |
| `wifi_capture_handshake` | Targeted capture on one AP to collect WPA handshake |

### ⚔️ Active Attacks

| Tool | Description |
|------|-------------|
| `wifi_deauth_attack` | `aireplay-ng -0` — send deauth frames to disconnect clients |
| `wifi_fake_auth` | `aireplay-ng -1` — fake-authenticate to a WEP AP |
| `wifi_arp_replay` | `aireplay-ng -3` — ARP replay to speed up WEP IV collection |

### 🔑 Cracking

| Tool | Description |
|------|-------------|
| `wifi_crack_password` | `aircrack-ng` dictionary attack on .cap file |
| `wifi_extract_handshakes` | List all handshakes in a capture file (no cracking) |

---

## Typical WPA2 Pentest Workflow

```
1. wifi_check_tools             → verify setup
2. wifi_list_interfaces         → find your adapter (e.g., wlan0)
3. wifi_kill_interfering_processes (dry_run=false)
4. wifi_enable_monitor_mode     → interface = "wlan0"  → gets "wlan0mon"
5. wifi_scan_networks           → interface = "wlan0mon", duration = 20
   (note target BSSID, channel, ESSID)
6. wifi_capture_handshake       → bssid, channel, interface, duration = 60
   (run simultaneously with step 7)
7. wifi_deauth_attack            → bssid, client = "FF:FF:FF:FF:FF:FF", count = 5
   (forces client re-auth → triggers 4-way handshake in capture)
8. wifi_extract_handshakes      → verify .cap has a handshake
9. wifi_crack_password          → capture_file, wordlist, bssid
10. wifi_disable_monitor_mode   → restore normal operation
```

## Typical WEP Pentest Workflow

```
1–4. Same as above
5. wifi_scan_networks           → identify WEP target
6. wifi_capture_handshake       → start capturing IVs
7. wifi_fake_auth               → associate with AP
8. wifi_arp_replay              → accelerate IV generation (need 50,000+ IVs)
9. wifi_crack_password          → aircrack-ng cracks WEP automatically from IVs
```

---

## Output Files

Capture files are saved to `/tmp/wifi_pentest_mcp/` by default.

| File | Contents |
|------|----------|
| `<prefix>-01.cap` | Raw packet capture (for cracking) |
| `<prefix>-01.csv` | Network/client list from airodump-ng |

---

## Wordlists

| Wordlist | Path |
|----------|------|
| rockyou  | `/usr/share/wordlists/rockyou.txt` (Kali default) |
| SecLists | `/usr/share/seclists/Passwords/` |
| Custom   | Any plaintext file, one password per line |

Uncompress rockyou if needed: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `airmon-ng` not found | `sudo apt install aircrack-ng` |
| Interface not in monitor mode | Run `wifi_enable_monitor_mode` first |
| No networks found | Check adapter supports monitor mode |
| No handshake captured | Run `wifi_deauth_attack` to force reconnect |
| "Permission denied" | Run server with `sudo` |
| Handshake not detected | Install tshark: `sudo apt install tshark` |

---

## Legal Disclaimer

This tool is provided for **educational and authorized security testing purposes only**.
The authors assume no liability for misuse. Always obtain explicit written authorization
before testing any network you do not own.
