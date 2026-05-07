#!/usr/bin/env python3
"""
WiFi Penetration Testing MCP Server
Wraps airmon-ng, airodump-ng, aireplay-ng, and aircrack-ng tools
for authorized wireless security assessments.
"""

import asyncio
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator

# ── Server ──────────────────────────────────────────────────────────────────
mcp = FastMCP(
    "wifi_pentest_mcp",
    instructions=(
        "WiFi penetration testing toolkit powered by the aircrack-ng suite. "
        "⚠️  FOR AUTHORIZED SECURITY TESTING ONLY. "
        "All operations must be performed on networks you own or have explicit written permission to test. "
        "Unauthorized access to computer networks is illegal."
    ),
)

# ── Constants ────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT = 30          # seconds for most commands
CAPTURE_TIMEOUT = 120         # seconds for passive captures
CRACK_TIMEOUT   = 3600        # seconds for cracking (1 hour max)
TEMP_DIR        = Path(tempfile.gettempdir()) / "wifi_pentest_mcp"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

REQUIRED_TOOLS = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = DEFAULT_TIMEOUT,
         stdin_data: Optional[str] = None) -> Dict[str, Any]:
    """Run a command and return stdout/stderr/returncode."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
            env={**os.environ, "TERM": "dumb"},
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": f"Command timed out after {timeout}s", "returncode": -1}
    except FileNotFoundError as e:
        return {"success": False, "stdout": "", "stderr": f"Tool not found: {e}", "returncode": -1}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}


def _tool_available(name: str) -> bool:
    r = _run(["which", name])
    return r["success"]


def _format_error(msg: str, hint: str = "") -> str:
    out = {"error": msg}
    if hint:
        out["hint"] = hint
    return json.dumps(out, indent=2)


def _parse_airodump_csv(csv_path: str) -> Dict[str, Any]:
    """Parse airodump-ng CSV output into structured data."""
    networks: List[Dict] = []
    clients:  List[Dict] = []

    try:
        with open(csv_path, "r", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return {"networks": [], "clients": []}

    section = "networks"
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("Station MAC"):
            section = "clients"
            continue

        parts = [p.strip() for p in line.split(",")]

        if section == "networks" and len(parts) >= 14:
            bssid = parts[0]
            if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                networks.append({
                    "bssid":   bssid,
                    "first_seen": parts[1],
                    "last_seen":  parts[2],
                    "channel":    parts[3].strip(),
                    "speed":      parts[4].strip(),
                    "privacy":    parts[5].strip(),
                    "cipher":     parts[6].strip(),
                    "auth":       parts[7].strip(),
                    "power":      parts[8].strip(),
                    "beacons":    parts[9].strip(),
                    "iv":         parts[10].strip(),
                    "lan_ip":     parts[11].strip(),
                    "id_length":  parts[12].strip(),
                    "essid":      parts[13].strip() if len(parts) > 13 else "",
                })

        elif section == "clients" and len(parts) >= 6:
            station = parts[0]
            if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", station):
                clients.append({
                    "station":    station,
                    "first_seen": parts[1],
                    "last_seen":  parts[2],
                    "power":      parts[3].strip(),
                    "packets":    parts[4].strip(),
                    "bssid":      parts[5].strip(),
                    "probed_essids": parts[6].strip() if len(parts) > 6 else "",
                })

    return {"networks": networks, "clients": clients}


# ── Input Models ─────────────────────────────────────────────────────────────

class InterfaceInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    interface: str = Field(..., description="Wireless interface name (e.g., 'wlan0', 'wlan1')", min_length=2, max_length=32)

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError("Interface name contains invalid characters")
        return v


class ScanInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    interface: str = Field(..., description="Monitor-mode interface (e.g., 'wlan0mon')", min_length=2, max_length=32)
    duration:  int = Field(default=15, description="Scan duration in seconds", ge=5, le=120)
    channel:   Optional[int] = Field(default=None, description="Lock to a specific channel (1-14 for 2.4 GHz, or 36-165 for 5 GHz)", ge=1, le=165)
    band:      Optional[str] = Field(default=None, description="Frequency band: 'a' (5 GHz), 'b' (2.4 GHz), 'abg' (all)")

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError("Interface name contains invalid characters")
        return v


class CaptureInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    interface: str = Field(..., description="Monitor-mode interface", min_length=2, max_length=32)
    bssid:     str = Field(..., description="Target AP BSSID (e.g., 'AA:BB:CC:DD:EE:FF')")
    channel:   int = Field(..., description="AP channel number", ge=1, le=165)
    duration:  int = Field(default=60, description="Capture duration in seconds", ge=10, le=600)
    output_prefix: str = Field(default="capture", description="Output file prefix (alphanumeric/underscore only)", max_length=32)

    @field_validator("bssid")
    @classmethod
    def validate_bssid(cls, v: str) -> str:
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", v):
            raise ValueError("BSSID must be in format AA:BB:CC:DD:EE:FF")
        return v.upper()

    @field_validator("output_prefix")
    @classmethod
    def validate_prefix(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError("Output prefix must be alphanumeric/underscore/dash only")
        return v

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError("Interface name contains invalid characters")
        return v


class DeauthInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    interface: str = Field(..., description="Monitor-mode interface", min_length=2, max_length=32)
    bssid:     str = Field(..., description="Target AP BSSID")
    client:    str = Field(default="FF:FF:FF:FF:FF:FF", description="Target client MAC (default: broadcast deauth)")
    count:     int = Field(default=5, description="Number of deauth frames to send (0 = continuous)", ge=0, le=100)

    @field_validator("bssid", "client")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", v):
            raise ValueError("MAC must be in format AA:BB:CC:DD:EE:FF")
        return v.upper()

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError("Interface name contains invalid characters")
        return v


class FakeAuthInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    interface: str = Field(..., description="Monitor-mode interface", min_length=2, max_length=32)
    bssid:     str = Field(..., description="Target AP BSSID")
    source_mac: Optional[str] = Field(default=None, description="Source MAC to use (defaults to card MAC)")
    delay:     int = Field(default=0, description="Delay between re-associations in seconds", ge=0, le=3600)

    @field_validator("bssid")
    @classmethod
    def validate_bssid(cls, v: str) -> str:
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", v):
            raise ValueError("BSSID must be in format AA:BB:CC:DD:EE:FF")
        return v.upper()

    @field_validator("source_mac")
    @classmethod
    def validate_source_mac(cls, v: Optional[str]) -> Optional[str]:
        if v and not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", v):
            raise ValueError("Source MAC must be in format AA:BB:CC:DD:EE:FF")
        return v.upper() if v else v

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError("Interface name contains invalid characters")
        return v


class ArpReplayInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    interface: str = Field(..., description="Monitor-mode interface", min_length=2, max_length=32)
    bssid:     str = Field(..., description="Target AP BSSID")
    source_mac: Optional[str] = Field(default=None, description="Source MAC override")
    duration:  int = Field(default=30, description="Duration in seconds", ge=5, le=300)

    @field_validator("bssid")
    @classmethod
    def validate_bssid(cls, v: str) -> str:
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", v):
            raise ValueError("BSSID must be in format AA:BB:CC:DD:EE:FF")
        return v.upper()

    @field_validator("source_mac")
    @classmethod
    def validate_source_mac(cls, v: Optional[str]) -> Optional[str]:
        if v and not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", v):
            raise ValueError("Source MAC must be in format AA:BB:CC:DD:EE:FF")
        return v.upper() if v else v

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError("Interface name contains invalid characters")
        return v


class CrackInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    capture_file: str = Field(..., description="Path to .cap/.pcap handshake file", max_length=256)
    wordlist:     str = Field(..., description="Path to wordlist file (e.g., /usr/share/wordlists/rockyou.txt)", max_length=256)
    bssid:        Optional[str] = Field(default=None, description="Filter by AP BSSID (optional)")
    essid:        Optional[str] = Field(default=None, description="Filter by ESSID/SSID (optional)", max_length=64)

    @field_validator("capture_file")
    @classmethod
    def validate_capture_file(cls, v: str) -> str:
        if not Path(v).exists():
            raise ValueError(f"Capture file not found: {v}")
        if not v.endswith((".cap", ".pcap", ".pcapng")):
            raise ValueError("Capture file must be .cap, .pcap, or .pcapng")
        return v

    @field_validator("wordlist")
    @classmethod
    def validate_wordlist(cls, v: str) -> str:
        if not Path(v).exists():
            raise ValueError(f"Wordlist file not found: {v}")
        return v

    @field_validator("bssid")
    @classmethod
    def validate_bssid(cls, v: Optional[str]) -> Optional[str]:
        if v and not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", v):
            raise ValueError("BSSID must be in format AA:BB:CC:DD:EE:FF")
        return v.upper() if v else v


class KillInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    dry_run: bool = Field(default=True, description="If True, only list processes; if False, kill them")


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool(
    name="wifi_check_tools",
    annotations={
        "title":        "Check Aircrack-ng Suite Installation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def wifi_check_tools() -> str:
    """
    Verify that airmon-ng, airodump-ng, aireplay-ng, and aircrack-ng are installed
    and accessible, and list available wireless interfaces.

    Returns:
        str: JSON with tool availability and wireless interface list.
    """
    tool_status = {}
    for tool in REQUIRED_TOOLS:
        r = _run(["which", tool])
        if r["success"]:
            # Get version
            ver = _run([tool, "--help"], timeout=5)
            first_line = (ver["stdout"] or ver["stderr"]).splitlines()[0] if (ver["stdout"] or ver["stderr"]) else "unknown"
            tool_status[tool] = {"available": True, "path": r["stdout"], "version_hint": first_line[:120]}
        else:
            tool_status[tool] = {"available": False, "path": None, "version_hint": None}

    # List wireless interfaces via iw or iwconfig
    iw_result   = _run(["iw", "dev"])
    iwc_result  = _run(["iwconfig"])
    interfaces_raw = iw_result["stdout"] or iwc_result["stdout"] or "Could not enumerate interfaces"

    # Also check if running as root
    uid = os.getuid()

    return json.dumps({
        "tools":          tool_status,
        "all_available":  all(v["available"] for v in tool_status.values()),
        "running_as_root": uid == 0,
        "interfaces_raw": interfaces_raw[:2000],
        "temp_dir":       str(TEMP_DIR),
        "warning":        "⚠️  Authorized testing only. Ensure you have written permission.",
    }, indent=2)


@mcp.tool(
    name="wifi_list_interfaces",
    annotations={
        "title":        "List Wireless Interfaces",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def wifi_list_interfaces() -> str:
    """
    List all available wireless network interfaces using airmon-ng.

    Returns:
        str: JSON with interface list including chipset and driver info.
    """
    r = _run(["airmon-ng"])
    if not r["success"] and not r["stdout"]:
        return _format_error(
            "airmon-ng not found or failed",
            "Install aircrack-ng: sudo apt install aircrack-ng",
        )

    output = r["stdout"] or r["stderr"]
    interfaces = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("PHY") and not line.startswith("Interface"):
            interfaces.append({
                "phy":       parts[0] if len(parts) > 0 else "",
                "interface": parts[1] if len(parts) > 1 else "",
                "driver":    parts[2] if len(parts) > 2 else "",
                "chipset":   " ".join(parts[3:]) if len(parts) > 3 else "",
            })

    return json.dumps({
        "interfaces":  interfaces,
        "raw_output":  output[:3000],
        "count":       len(interfaces),
    }, indent=2)


@mcp.tool(
    name="wifi_enable_monitor_mode",
    annotations={
        "title":           "Enable Monitor Mode (airmon-ng start)",
        "readOnlyHint":    False,
        "destructiveHint": False,
        "idempotentHint":  False,
        "openWorldHint":   False,
    },
)
async def wifi_enable_monitor_mode(params: InterfaceInput) -> str:
    """
    Enable monitor mode on a wireless interface using airmon-ng.
    Usually creates a new interface like wlan0mon.

    Args:
        params (InterfaceInput):
            - interface (str): Wireless interface (e.g., 'wlan0')

    Returns:
        str: JSON with result and new monitor-mode interface name.
    """
    if not _tool_available("airmon-ng"):
        return _format_error("airmon-ng not found", "sudo apt install aircrack-ng")

    r = _run(["airmon-ng", "start", params.interface])
    output = r["stdout"] + "\n" + r["stderr"]

    # Try to detect new interface name
    mon_iface = None
    for pattern in [r"monitor mode (vif )?enabled (on|for) (\w+)", r"(wlan\d+mon|mon\d+)"]:
        m = re.search(pattern, output, re.IGNORECASE)
        if m:
            mon_iface = m.group(m.lastindex)
            break
    if not mon_iface:
        mon_iface = params.interface + "mon"

    return json.dumps({
        "success":            r["success"] or "monitor mode" in output.lower(),
        "original_interface": params.interface,
        "monitor_interface":  mon_iface,
        "output":             output[:2000],
        "next_step":          f"Use '{mon_iface}' in scan/capture tools",
    }, indent=2)


@mcp.tool(
    name="wifi_disable_monitor_mode",
    annotations={
        "title":           "Disable Monitor Mode (airmon-ng stop)",
        "readOnlyHint":    False,
        "destructiveHint": False,
        "idempotentHint":  False,
        "openWorldHint":   False,
    },
)
async def wifi_disable_monitor_mode(params: InterfaceInput) -> str:
    """
    Disable monitor mode and restore a wireless interface to managed mode.

    Args:
        params (InterfaceInput):
            - interface (str): Monitor-mode interface to stop (e.g., 'wlan0mon')

    Returns:
        str: JSON with result and restored interface name.
    """
    if not _tool_available("airmon-ng"):
        return _format_error("airmon-ng not found", "sudo apt install aircrack-ng")

    r = _run(["airmon-ng", "stop", params.interface])
    output = r["stdout"] + "\n" + r["stderr"]

    return json.dumps({
        "success": r["success"] or "monitor mode disabled" in output.lower(),
        "interface_stopped": params.interface,
        "output":  output[:2000],
    }, indent=2)


@mcp.tool(
    name="wifi_kill_interfering_processes",
    annotations={
        "title":           "Kill Interfering Processes (airmon-ng check kill)",
        "readOnlyHint":    False,
        "destructiveHint": True,
        "idempotentHint":  False,
        "openWorldHint":   False,
    },
)
async def wifi_kill_interfering_processes(params: KillInput) -> str:
    """
    Check for (and optionally kill) processes that interfere with monitor mode,
    such as NetworkManager, wpa_supplicant, and dhclient.

    Args:
        params (KillInput):
            - dry_run (bool): True = list only; False = kill processes (requires root)

    Returns:
        str: JSON with found processes and kill results.
    """
    if not _tool_available("airmon-ng"):
        return _format_error("airmon-ng not found", "sudo apt install aircrack-ng")

    check_r = _run(["airmon-ng", "check"])
    output  = check_r["stdout"] + "\n" + check_r["stderr"]

    if params.dry_run:
        return json.dumps({
            "dry_run":   True,
            "processes": output[:3000],
            "message":   "Set dry_run=false to actually kill these processes",
        }, indent=2)

    kill_r = _run(["airmon-ng", "check", "kill"])
    kill_output = kill_r["stdout"] + "\n" + kill_r["stderr"]
    return json.dumps({
        "dry_run":     False,
        "check_output": output[:1500],
        "kill_output":  kill_output[:1500],
        "success":      kill_r["success"],
    }, indent=2)


@mcp.tool(
    name="wifi_scan_networks",
    annotations={
        "title":           "Scan for Wireless Networks (airodump-ng)",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  False,
        "openWorldHint":   True,
    },
)
async def wifi_scan_networks(params: ScanInput) -> str:
    """
    Passively scan for nearby wireless networks and clients using airodump-ng.
    Returns a structured list of access points and connected clients.

    Args:
        params (ScanInput):
            - interface (str): Monitor-mode interface (e.g., 'wlan0mon')
            - duration  (int): Scan seconds (5–120, default 15)
            - channel   (int): Lock to channel (optional)
            - band      (str): 'a', 'b', or 'abg' (optional)

    Returns:
        str: JSON with networks[] and clients[] arrays.
    """
    if not _tool_available("airodump-ng"):
        return _format_error("airodump-ng not found", "sudo apt install aircrack-ng")

    prefix = TEMP_DIR / f"scan_{int(time.time())}"
    cmd = [
        "airodump-ng",
        "--write",        str(prefix),
        "--output-format", "csv",
        "--write-interval", "1",
    ]
    if params.channel:
        cmd += ["--channel", str(params.channel)]
    if params.band:
        cmd += ["--band", params.band]
    cmd.append(params.interface)

    # Run airodump-ng in background, kill after duration
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        await asyncio.sleep(params.duration)
    finally:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
            proc.wait()

    csv_file = str(prefix) + "-01.csv"
    data = _parse_airodump_csv(csv_file)

    # Clean up temp files
    for ext in ["-01.csv", "-01.cap", "-01.kismet.csv", "-01.kismet.netxml", "-01.log.csv"]:
        try:
            Path(str(prefix) + ext).unlink(missing_ok=True)
        except Exception:
            pass

    return json.dumps({
        "scan_duration_s": params.duration,
        "interface":       params.interface,
        "networks_found":  len(data["networks"]),
        "clients_found":   len(data["clients"]),
        "networks":        data["networks"],
        "clients":         data["clients"],
    }, indent=2)


@mcp.tool(
    name="wifi_capture_handshake",
    annotations={
        "title":           "Capture WPA Handshake (airodump-ng targeted)",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  False,
        "openWorldHint":   True,
    },
)
async def wifi_capture_handshake(params: CaptureInput) -> str:
    """
    Targeted capture on a specific AP to collect WPA/WPA2 4-way handshakes.
    Save the .cap file for offline cracking with wifi_crack_password.

    Args:
        params (CaptureInput):
            - interface     (str): Monitor-mode interface
            - bssid         (str): Target AP BSSID
            - channel       (int): AP channel
            - duration      (int): Capture duration 10–600s (default 60)
            - output_prefix (str): File prefix (saved to /tmp/wifi_pentest_mcp/)

    Returns:
        str: JSON with capture file path and frame count summary.
    """
    if not _tool_available("airodump-ng"):
        return _format_error("airodump-ng not found", "sudo apt install aircrack-ng")

    prefix = TEMP_DIR / params.output_prefix
    cmd = [
        "airodump-ng",
        "--bssid",         params.bssid,
        "--channel",       str(params.channel),
        "--write",         str(prefix),
        "--output-format", "pcap,csv",
        "--write-interval", "2",
        params.interface,
    ]

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        await asyncio.sleep(params.duration)
    finally:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
            proc.wait()

    cap_file = str(prefix) + "-01.cap"
    csv_file = str(prefix) + "-01.csv"
    cap_exists = Path(cap_file).exists()
    cap_size = Path(cap_file).stat().st_size if cap_exists else 0

    csv_data = _parse_airodump_csv(csv_file)
    target_net = next((n for n in csv_data["networks"] if n["bssid"] == params.bssid), {})

    # Check for EAPOL (handshake) frames via tshark if available
    handshake_detected = False
    if cap_exists and _tool_available("tshark"):
        eapol = _run(["tshark", "-r", cap_file, "-Y", "eapol", "-c", "4"], timeout=15)
        if eapol["success"] and eapol["stdout"]:
            handshake_detected = True

    return json.dumps({
        "capture_file":        cap_file if cap_exists else None,
        "capture_size_bytes":  cap_size,
        "bssid":               params.bssid,
        "essid":               target_net.get("essid", "unknown"),
        "channel":             params.channel,
        "duration_s":          params.duration,
        "handshake_detected":  handshake_detected,
        "clients_seen":        len(csv_data["clients"]),
        "next_steps": [
            "Run wifi_deauth_attack to force client reconnect (triggers handshake)",
            f"Run wifi_crack_password with capture_file='{cap_file}' to crack",
        ] if cap_exists else ["Capture file not created — check interface is in monitor mode"],
    }, indent=2)


@mcp.tool(
    name="wifi_deauth_attack",
    annotations={
        "title":           "Send Deauth Frames (aireplay-ng -0)",
        "readOnlyHint":    False,
        "destructiveHint": True,
        "idempotentHint":  False,
        "openWorldHint":   True,
    },
)
async def wifi_deauth_attack(params: DeauthInput) -> str:
    """
    Send 802.11 deauthentication frames to disconnect a client from an AP.
    Useful for forcing a WPA handshake when combined with wifi_capture_handshake.
    ⚠️  Authorized testing only. Disconnects real clients.

    Args:
        params (DeauthInput):
            - interface (str): Monitor-mode interface
            - bssid     (str): Target AP BSSID
            - client    (str): Client MAC (default: FF:FF:FF:FF:FF:FF broadcast)
            - count     (int): Frames to send 1–100 (default 5); 0 = continuous

    Returns:
        str: JSON with aireplay-ng output.
    """
    if not _tool_available("aireplay-ng"):
        return _format_error("aireplay-ng not found", "sudo apt install aircrack-ng")

    cmd = [
        "aireplay-ng",
        "--deauth", str(params.count),
        "-a", params.bssid,
        "-c", params.client,
        params.interface,
    ]

    timeout = 30 if params.count > 0 else 10
    r = _run(cmd, timeout=timeout)
    output = r["stdout"] + "\n" + r["stderr"]

    return json.dumps({
        "success":   r["success"] or "sent" in output.lower(),
        "bssid":     params.bssid,
        "client":    params.client,
        "count":     params.count,
        "interface": params.interface,
        "output":    output[:2000],
        "tip":       "Combine with wifi_capture_handshake running simultaneously to catch re-auth",
    }, indent=2)


@mcp.tool(
    name="wifi_fake_auth",
    annotations={
        "title":           "Fake Authentication (aireplay-ng -1)",
        "readOnlyHint":    False,
        "destructiveHint": False,
        "idempotentHint":  False,
        "openWorldHint":   True,
    },
)
async def wifi_fake_auth(params: FakeAuthInput) -> str:
    """
    Perform a fake authentication against a WEP access point (aireplay-ng -1).
    Required before ARP replay attacks on WEP networks to associate with the AP.

    Args:
        params (FakeAuthInput):
            - interface  (str): Monitor-mode interface
            - bssid      (str): Target AP BSSID
            - source_mac (str): Source MAC override (optional)
            - delay      (int): Re-association delay seconds (default 0)

    Returns:
        str: JSON with authentication result.
    """
    if not _tool_available("aireplay-ng"):
        return _format_error("aireplay-ng not found", "sudo apt install aircrack-ng")

    cmd = [
        "aireplay-ng",
        "--fakeauth", str(params.delay),
        "-a", params.bssid,
    ]
    if params.source_mac:
        cmd += ["-h", params.source_mac]
    cmd.append(params.interface)

    r = _run(cmd, timeout=DEFAULT_TIMEOUT)
    output = r["stdout"] + "\n" + r["stderr"]

    return json.dumps({
        "success":   r["success"] or "association successful" in output.lower(),
        "bssid":     params.bssid,
        "interface": params.interface,
        "output":    output[:2000],
    }, indent=2)


@mcp.tool(
    name="wifi_arp_replay",
    annotations={
        "title":           "ARP Request Replay Attack (aireplay-ng -3)",
        "readOnlyHint":    False,
        "destructiveHint": False,
        "idempotentHint":  False,
        "openWorldHint":   True,
    },
)
async def wifi_arp_replay(params: ArpReplayInput) -> str:
    """
    Launch an ARP request replay attack (aireplay-ng -3) against a WEP network
    to accelerate IV collection for aircrack-ng.

    Args:
        params (ArpReplayInput):
            - interface  (str): Monitor-mode interface
            - bssid      (str): Target AP BSSID
            - source_mac (str): Source MAC override (optional)
            - duration   (int): Attack duration 5–300s (default 30)

    Returns:
        str: JSON with packet counts and replay stats.
    """
    if not _tool_available("aireplay-ng"):
        return _format_error("aireplay-ng not found", "sudo apt install aircrack-ng")

    cmd = [
        "aireplay-ng",
        "--arpreplay",
        "-b", params.bssid,
    ]
    if params.source_mac:
        cmd += ["-h", params.source_mac]
    cmd.append(params.interface)

    proc = None
    stdout_lines: List[str] = []
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid,
        )
        start = time.time()
        while time.time() - start < params.duration:
            line = proc.stdout.readline() if proc.stdout else ""
            if line:
                stdout_lines.append(line.rstrip())
            await asyncio.sleep(0.1)
    finally:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
            proc.wait()

    output = "\n".join(stdout_lines[-50:])  # last 50 lines
    # Parse final packet count from output
    packets_sent = 0
    for line in reversed(stdout_lines):
        m = re.search(r"(\d+)\s+packets", line)
        if m:
            packets_sent = int(m.group(1))
            break

    return json.dumps({
        "bssid":        params.bssid,
        "interface":    params.interface,
        "duration_s":   params.duration,
        "packets_sent": packets_sent,
        "output_tail":  output[:2000],
        "next_step":    "Run wifi_crack_password on your .cap file once you have enough IVs (>50,000 for WEP)",
    }, indent=2)


@mcp.tool(
    name="wifi_crack_password",
    annotations={
        "title":           "Crack WPA/WEP Password (aircrack-ng)",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   False,
    },
)
async def wifi_crack_password(params: CrackInput) -> str:
    """
    Attempt to recover a WPA/WPA2 passphrase or WEP key from a capture file
    using a dictionary wordlist with aircrack-ng.

    Args:
        params (CrackInput):
            - capture_file (str): Path to .cap/.pcap file with handshake
            - wordlist     (str): Path to wordlist (e.g., /usr/share/wordlists/rockyou.txt)
            - bssid        (str): Filter to specific AP BSSID (optional)
            - essid        (str): Filter to specific SSID (optional)

    Returns:
        str: JSON with cracking result — key found or not found.
    """
    if not _tool_available("aircrack-ng"):
        return _format_error("aircrack-ng not found", "sudo apt install aircrack-ng")

    cmd = ["aircrack-ng", "-w", params.wordlist]
    if params.bssid:
        cmd += ["-b", params.bssid]
    if params.essid:
        cmd += ["-e", params.essid]
    cmd.append(params.capture_file)

    r = _run(cmd, timeout=CRACK_TIMEOUT)
    output = r["stdout"] + "\n" + r["stderr"]

    # Parse result
    key_found    = False
    key_value    = None
    tested_keys  = None

    if "KEY FOUND!" in output:
        key_found = True
        m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
        if m:
            key_value = m.group(1)
    elif "Passphrase not in dictionary" in output:
        key_found = False

    m = re.search(r"(\d+[\d,]*)\s+keys tested", output)
    if m:
        tested_keys = m.group(1)

    return json.dumps({
        "key_found":   key_found,
        "key":         key_value,
        "keys_tested": tested_keys,
        "capture_file": params.capture_file,
        "wordlist":    params.wordlist,
        "output_tail": output[-2000:],
        "tip": (
            "Try a larger wordlist or use hashcat with rules for better coverage"
            if not key_found else "Password recovered successfully"
        ),
    }, indent=2)


@mcp.tool(
    name="wifi_extract_handshakes",
    annotations={
        "title":        "List/Verify Handshakes in Capture File",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def wifi_extract_handshakes(params: CrackInput) -> str:
    """
    Analyze a .cap file with aircrack-ng to list all WPA handshakes it contains
    without running a full crack. Useful to verify a capture before cracking.

    Args:
        params (CrackInput):
            - capture_file (str): Path to .cap/.pcap file
            - wordlist     (str): Any valid path (not used for analysis, required by model)
            - bssid        (str): Filter by BSSID (optional)
            - essid        (str): Filter by SSID (optional)

    Returns:
        str: JSON list of networks with handshakes found in the capture.
    """
    if not _tool_available("aircrack-ng"):
        return _format_error("aircrack-ng not found", "sudo apt install aircrack-ng")

    # Use -l /dev/null trick to just list networks
    cmd = ["aircrack-ng", params.capture_file]
    r = _run(cmd, timeout=30, stdin_data="\n")  # send newline to skip interactive prompt
    output = r["stdout"] + "\n" + r["stderr"]

    # Parse index table
    networks = []
    in_table = False
    for line in output.splitlines():
        if "BSSID" in line and "ESSID" in line:
            in_table = True
            continue
        if in_table and re.match(r"\s*\d+", line):
            parts = line.split()
            if len(parts) >= 3:
                networks.append({
                    "index":     parts[0].strip("#"),
                    "bssid":     parts[1] if len(parts) > 1 else "",
                    "essid":     parts[-1] if len(parts) > 2 else "",
                    "handshake": "handshake" in line.lower() or "WPA" in line,
                })

    return json.dumps({
        "capture_file":    params.capture_file,
        "networks_found":  len(networks),
        "networks":        networks,
        "raw_output":      output[:3000],
    }, indent=2)


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
