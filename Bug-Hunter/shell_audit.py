#!/usr/bin/env python3
"""
Bug Hunter v2 — credentialed shell audit + low-level firmware dump
==================================================================

Opens a shell on the operator's OWN router using credentials the operator
typed — never via an unauthenticated bypass, never via injected payloads —
and then:

  * runs a fixed list of READ-ONLY enumeration commands
    (no writes, no reboot, no kill, no config change),
  * confirms uid (root vs non-root), kernel, SoC, MTD layout,
  * optionally dumps MTD partitions (low-level firmware) via base64/hex
    over the same shell, decoded and hashed locally.

Transports: Telnet (raw-socket client below, works everywhere incl.
Termux) and SSH (system `ssh` binary via subprocess; `sshpass` only if
the operator installed it for password login, else key-based).

Every transcript is secret-redacted before it is shown or saved. LAN-only
is enforced by the caller (bug_hunter.resolve_private).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import shutil
import socket
import stat
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"
SEV_INFO = "INFO"

# --------------------------------------------------------------------------- #
# Secret redaction — applied to every byte shown or saved from a shell.
# --------------------------------------------------------------------------- #

_REDACT_RES = [
    re.compile(r"(?i)(password|passwd|psk|passphrase|presharedkey|secret|wpa[_-]?key"
               r"|wep[_-]?key|admin[_-]?pass|root[_-]?pass)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(psk|password|passphrase)\s+['\"][^'\"]+['\"]"),
    re.compile(r"(?i)(http://[^/\s]*:)([^@/\s]+)(@)"),
]


def redact_secrets(text: str) -> str:
    if not text:
        return text
    out = text
    out = _REDACT_RES[0].sub(lambda m: m.group(0).split(":")[0].split("=")[0] + "=[REDACTED]", out)
    out = _REDACT_RES[1].sub(lambda m: m.group(1) + " [REDACTED]", out)
    out = _REDACT_RES[2].sub(r"\1[REDACTED]\3", out)
    return out


# --------------------------------------------------------------------------- #
# Minimal Telnet client (raw sockets, IAC negotiation = refuse everything)
# --------------------------------------------------------------------------- #

_IAC = b"\xff"
_WILL = b"\xfb"
_WONT = b"\xfc"
_DO = b"\xfd"
_DONT = b"\xfe"


class TelnetClient:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.buf = b""

    def connect(self, host: str, port: int = 23) -> None:
        sock = socket.create_connection((host, port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        self.sock = sock
        self.buf = b""

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _send(self, data: bytes) -> None:
        assert self.sock is not None
        self.sock.sendall(data.replace(b"\xff", b"\xff\xff"))

    def _negotiate(self, data: bytes) -> bytes:
        """Strip IAC sequences, refusing all options. Returns clean bytes."""
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i:i + 1] == _IAC and i + 2 < len(data) + 1:
                if i + 1 >= len(data):
                    break
                cmd = data[i + 1:i + 2]
                if cmd in (_WILL, _WONT):
                    opt = data[i + 2:i + 3] if i + 2 < len(data) else b"\x00"
                    try:
                        assert self.sock is not None
                        self.sock.sendall(_IAC + _DONT + opt)
                    except OSError:
                        pass
                    i += 3
                elif cmd in (_DO, _DONT):
                    opt = data[i + 2:i + 3] if i + 2 < len(data) else b"\x00"
                    try:
                        assert self.sock is not None
                        self.sock.sendall(_IAC + _WONT + opt)
                    except OSError:
                        pass
                    i += 3
                elif cmd == _IAC:
                    out.append(0xFF)
                    i += 2
                else:
                    i += 2
            else:
                out.append(data[i])
                i += 1
        return bytes(out)

    def read_until(self, patterns: List[bytes], timeout: Optional[float] = None) -> bytes:
        """Read until any pattern matches (case-insensitive) or timeout."""
        assert self.sock is not None
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        lowered = [p.lower() for p in patterns]
        data = self.buf
        self.buf = b""
        self.sock.settimeout(1.0)
        while time.time() < deadline:
            low = data.lower()
            for pat in lowered:
                if pat in low:
                    # Keep trailing bytes for the next read.
                    idx = low.find(pat) + len(pat)
                    self.buf = data[idx:]
                    return data[:idx]
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            data += self._negotiate(chunk)
        self.buf = b""
        return data

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """Wait for login:/password: prompts and submit owner creds."""
        banner = self.read_until([b"login:", b"username:", b"user:", b"password:"],
                                 timeout=self.timeout)
        text = banner.decode("utf-8", "replace")
        if b"password:" in banner.lower() and b"login:" not in banner.lower() \
                and b"username:" not in banner.lower() and b"user:" not in banner.lower():
            pass  # password-first boxes (rare)
        else:
            if not re.search(r"login:|username:|user:", text, re.I):
                return False, text
            self._send(username.encode("utf-8", "replace") + b"\r\n")
            pw = self.read_until([b"password:"], timeout=self.timeout)
            text += pw.decode("utf-8", "replace")
            if b"password:" not in pw.lower():
                return False, text
        self._send(password.encode("utf-8", "replace") + b"\r\n")
        shell = self.read_until([b"#", b"$", b">", b"incorrect", b"failed",
                                 b"bad", b"denied", b"login:"],
                                timeout=self.timeout)
        text += shell.decode("utf-8", "replace")
        low = shell.lower()
        if any(w in low for w in (b"incorrect", b"failed", b"bad ", b"denied")):
            return False, text
        if b"login:" in low:
            return False, text  # back at login = rejected
        return True, text

    def exec(self, cmd: str, timeout: float = 12.0) -> str:
        """Run one command, return output (echo + prompt stripped, best-effort)."""
        assert self.sock is not None
        marker = f"BH_END_{os.getpid()}_{int(time.time() * 1000) % 100000}"
        self._send(f"{cmd}; echo {marker}\r\n".encode("utf-8", "replace"))
        raw = self.read_until([marker.encode()], timeout=timeout)
        text = raw.decode("utf-8", "replace")
        # Strip the echoed command line and the marker line. The echo starts
        # with the command itself (a substring test would eat real output
        # like "uid=..." for the `id` command).
        lines = text.splitlines()
        first_word = cmd.split()[0] if cmd.split() else ""
        if lines and first_word and lines[0].strip().startswith(first_word):
            # Only an echo if the line also looks like our full command.
            if lines[0].strip().startswith(cmd[:24]) or "echo BH_END_" in lines[0]:
                lines = lines[1:]
        lines = [ln for ln in lines if marker not in ln]
        # Strip a trailing prompt fragment.
        if lines and re.match(r"^\S*[#$>]\s*$", lines[-1].strip()):
            lines = lines[:-1]
        # Drop leading blanks, then a leftover prompt from the previous
        # response ("# mtd0: ..." -> "mtd0: ..."). The prompt char must be
        # at column 0 followed by whitespace to qualify.
        while lines and not lines[0].strip():
            lines = lines[1:]
        if lines:
            stripped = re.sub(r"^[#$>][ \t]+", "", lines[0], count=1)
            if stripped != lines[0]:
                lines[0] = stripped
        return "\n".join(lines).strip()


# Fixed read-only enumeration. Nothing here writes, kills, or reboots.
READONLY_COMMANDS: List[Tuple[str, str]] = [
    ("uid", "id"),
    ("user", "whoami; echo HOST:$HOSTNAME"),
    ("kernel", "cat /proc/version"),
    ("cpu", "cat /proc/cpuinfo | head -20"),
    ("mtd", "cat /proc/mtd"),
    ("cmdline", "cat /proc/cmdline"),
    ("mem", "cat /proc/meminfo | head -5; free 2>/dev/null | head -4"),
    ("mounts", "cat /proc/mounts"),
    ("busybox", "busybox 2>&1 | head -2; cat /etc/banner 2>/dev/null | head -5"),
    ("uptime", "uptime; cat /proc/uptime"),
    ("net", "ifconfig 2>/dev/null | head -30 || ip addr 2>/dev/null | head -30"),
    ("services", "ps 2>/dev/null | head -25 || ps w 2>/dev/null | head -25"),
    ("httpd", "ps 2>/dev/null | grep -i -E 'http|boa|lighttp|uhttpd|goahead' | head -5"),
    ("nvram_model", "nvram get model 2>/dev/null; nvram get firmware_version 2>/dev/null; "
                    "uci get system.@system[0].hostname 2>/dev/null"),
]

_MTD_LINE_RE = re.compile(
    r'^(mtd\d+):\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"([^"]+)"', re.M)


def parse_mtd_table(text: str) -> List[Dict[str, Any]]:
    parts = []
    for m in _MTD_LINE_RE.finditer(text or ""):
        try:
            size = int(m.group(2), 16)
        except ValueError:
            size = 0
        parts.append({"dev": m.group(1), "size": size, "size_hex": m.group(2),
                      "name": m.group(4)})
    return parts


def _kernel_age_note(version_line: str) -> Optional[Tuple[str, str, str]]:
    """Return (finding_id, severity, note) for ancient kernels."""
    m = re.search(r"Linux version (\d+)\.(\d+)", version_line or "")
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    if (major, minor) < (3, 10):
        return ("SHELL-003", SEV_HIGH,
                f"Kernel {major}.{minor} predates 3.10 (2013) — no upstream "
                "security fixes for a decade or more.")
    if (major, minor) < (4, 4):
        return ("SHELL-003", SEV_MEDIUM,
                f"Kernel {major}.{minor} predates 4.4 (2016 LTS) — almost "
                "certainly EOL on this vendor tree.")
    return None


def run_telnet_audit(host: str, username: str, password: str,
                     port: int = 23, timeout: float = 10.0,
                     verbose: bool = False,
                     via_defaults: bool = False) -> Dict[str, Any]:
    """Full Telnet audit. Returns {ok, error, facts, findings, transcript}."""
    result: Dict[str, Any] = {"transport": "telnet", "ok": False, "error": None,
                              "facts": {}, "findings": [], "transcript": ""}
    if via_defaults:
        result["via_defaults"] = True
    tn = TelnetClient(timeout=timeout)
    transcript: List[str] = []
    try:
        try:
            tn.connect(host, port)
        except (OSError, socket.timeout) as exc:
            result["error"] = f"Telnet connect failed: {exc}"
            return result
        ok, banner = tn.login(username, password)
        transcript.append(f"$ <connect {host}:{port}>\n{banner}")
        if not ok:
            result["error"] = (f"Telnet login as '{username}' rejected "
                               "(wrong password or Telnet needs a different user)")
            result["transcript"] = redact_secrets("\n".join(transcript))
            return result
        result["ok"] = True
        outputs: Dict[str, str] = {}
        for name, cmd in READONLY_COMMANDS:
            try:
                out = tn.exec(cmd)
            except Exception as exc:  # noqa: BLE001 — keep auditing
                out = f"<command error: {exc}>"
            outputs[name] = out
            transcript.append(f"$ {cmd}\n{out}")
            if verbose:
                print(f"    [+] shell:{name} ({len(out)} bytes)")

        facts: Dict[str, Any] = {"commands": len(outputs)}
        uid_out = outputs.get("uid", "")
        m = re.search(r"uid=(\d+)\(([^)]+)\)", uid_out)
        if m:
            facts["uid"] = int(m.group(1))
            facts["shell_user"] = m.group(2)
            facts["is_root"] = facts["uid"] == 0
        kernel = outputs.get("kernel", "")
        if kernel:
            facts["kernel"] = kernel.splitlines()[0][:160] if kernel else None
        mtd_parts = parse_mtd_table(outputs.get("mtd", ""))
        if mtd_parts:
            facts["mtd_partitions"] = mtd_parts
            facts["mtd_total_bytes"] = sum(p["size"] for p in mtd_parts)
        cpu = outputs.get("cpu", "")
        m = re.search(r"(?:model name|cpu model|system type)\s*:\s*(.+)", cpu, re.I)
        if m:
            facts["cpu"] = m.group(1).strip()[:96]
        if outputs.get("uptime"):
            facts["uptime"] = outputs["uptime"].splitlines()[0][:96]
        nv = outputs.get("nvram_model", "").strip()
        if nv and "error" not in nv.lower():
            facts["nvram"] = nv[:160]
        result["facts"] = facts

        findings: List[Dict] = []
        if facts.get("is_root"):
            findings.append({
                "id": "SHELL-001",
                "title": "Credentialed shell confirmed ROOT (uid=0)",
                "severity": SEV_HIGH if via_defaults else SEV_INFO,
                "confidence": "CONFIRMED",
                "cve": "N/A (administrative access)",
                "description": (
                    f"Login as '{username}' over Telnet yielded uid=0 (root). "
                    "With the owner's own credentials this is the expected "
                    "admin path — noted as the basis for the low-level dump. "
                    + ("Because these were factory-default credentials, anyone "
                       "on the LAN gets the same root shell — change them now."
                       if via_defaults else
                       "This is NOT a vulnerability finding on its own.")),
                "url": f"telnet://{host}/",
                "impact": ("Full device control for whoever holds these "
                           "credentials." if via_defaults else
                           "Operator confirmed admin-level shell; enables MTD dump."),
                "fix": ("Change the Telnet/admin password immediately; disable "
                        "Telnet if SSH exists." if via_defaults else
                        "No action — keep these credentials safe; disable Telnet "
                        "from WAN."),
                "urls": [],
            })
        elif facts.get("uid") is not None:
            findings.append({
                "id": "SHELL-001",
                "title": f"Credentialed shell confirmed (uid={facts['uid']}, non-root)",
                "severity": SEV_INFO,
                "confidence": "CONFIRMED",
                "cve": "N/A (administrative access)",
                "description": (
                    f"Login as '{username}' works but is not root "
                    f"(uid={facts['uid']}). MTD dump may need root; try the "
                    "admin/root account."),
                "url": f"telnet://{host}/",
                "impact": "Limited shell; low-level dump may be unavailable.",
                "fix": "Re-run with the admin/root credentials if a dump is needed.",
                "urls": [],
            })
        age = _kernel_age_note(kernel)
        if age:
            fid, sev, note = age
            findings.append({
                "id": fid, "title": "Ancient kernel on the live unit",
                "severity": sev, "confidence": "CONFIRMED",
                "cve": "N/A (patch-gap class)",
                "description": f"/proc/version: {kernel[:200]} {note}",
                "url": f"telnet://{host}/",
                "impact": "Years of unpatched local/adjacent kernel CVEs.",
                "fix": ("Ask the vendor/ISP for a current build; if EOL, bridge "
                        "the unit and route behind hardware you control."),
                "urls": [],
            })
        services = outputs.get("services", "").lower()
        if "telnetd" in services and facts.get("is_root"):
            findings.append({
                "id": "SHELL-004",
                "title": "telnetd confirmed running (plaintext admin shell)",
                "severity": SEV_MEDIUM,
                "confidence": "CONFIRMED",
                "cve": "N/A (insecure service)",
                "description": ("Process list shows telnetd. Credentials and "
                                "shell traffic cross the LAN in cleartext."),
                "url": f"telnet://{host}/",
                "impact": "LAN eavesdropper captures admin credentials.",
                "fix": "Prefer SSH; disable Telnet if the firmware allows it.",
                "urls": [],
            })
        result["findings"] = findings
    finally:
        tn.close()
        result["transcript"] = redact_secrets("\n".join(transcript))
    return result


# --------------------------------------------------------------------------- #
# MTD dump over an open Telnet session
# --------------------------------------------------------------------------- #

def _decode_base64_blob(text: str) -> bytes:
    cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", text)
    # base64 stream may be wrapped; pad if needed.
    cleaned += "=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned, validate=False)


def dump_mtd_via_telnet(host: str, username: str, password: str,
                        partition: str, outpath: str,
                        port: int = 23, timeout: float = 10.0,
                        verbose: bool = False) -> Dict[str, Any]:
    """Dump /dev/<partition> over Telnet using base64 (or hexdump fallback).

    Read-only on the device; writes only to the local outpath (0600).
    """
    res: Dict[str, Any] = {"ok": False, "error": None, "path": None,
                           "bytes": 0, "sha256": None, "method": None}
    if not re.fullmatch(r"mtd\d+", partition):
        res["error"] = f"refusing suspicious partition name {partition!r}"
        return res
    tn = TelnetClient(timeout=timeout)
    try:
        tn.connect(host, port)
        ok, _ = tn.login(username, password)
        if not ok:
            res["error"] = "Telnet login rejected"
            return res
        has_b64 = tn.exec("which base64; base64 --help 2>&1 | head -1")
        if "base64" in has_b64.lower() and "not found" not in has_b64.lower():
            if verbose:
                print(f"    [*] dumping /dev/{partition} via base64 ...")
            blob = tn.exec(f"base64 /dev/{partition}", timeout=300.0)
            try:
                raw = _decode_base64_blob(blob)
            except (binascii.Error, ValueError) as exc:
                res["error"] = f"base64 decode failed: {exc}"
                return res
            res["method"] = "base64"
        else:
            if verbose:
                print("    [*] no base64 on device; trying hexdump ...")
            blob = tn.exec(f"hexdump -v -e '1/1 \"%02x\"' /dev/{partition}",
                           timeout=300.0)
            cleaned = re.sub(r"[^0-9a-fA-F]", "", blob)
            if len(cleaned) < 64 or len(cleaned) % 2:
                res["error"] = ("device has neither base64 nor usable hexdump; "
                                "dump not possible over this shell")
                return res
            try:
                raw = bytes.fromhex(cleaned)
            except ValueError as exc:
                res["error"] = f"hex decode failed: {exc}"
                return res
            res["method"] = "hexdump"
        if not raw:
            res["error"] = "empty dump (bad partition or permission denied)"
            return res
        with open(outpath, "wb") as fh:
            fh.write(raw)
        try:
            os.chmod(outpath, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        res.update(ok=True, path=outpath, bytes=len(raw),
                   sha256=hashlib.sha256(raw).hexdigest())
        return res
    except (OSError, Exception) as exc:  # noqa: BLE001
        res["error"] = f"dump failed: {exc}"
        return res
    finally:
        tn.close()


# --------------------------------------------------------------------------- #
# SSH transport — system `ssh` binary (no Python SSH deps exist in stdlib).
# --------------------------------------------------------------------------- #

def ssh_available() -> bool:
    return shutil.which("ssh") is not None


def sshpass_available() -> bool:
    return shutil.which("sshpass") is not None


def _ssh_base(host: str, username: str, port: int, timeout: int) -> List[str]:
    return ["ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=%d" % timeout,
            "-o", "BatchMode=no",
            "-p", str(port), f"{username}@{host}"]


def run_ssh_audit(host: str, username: str, password: Optional[str] = None,
                  port: int = 22, timeout: int = 12,
                  verbose: bool = False,
                  via_defaults: bool = False) -> Dict[str, Any]:
    """Run the same read-only commands over the system ssh binary."""
    result: Dict[str, Any] = {"transport": "ssh", "ok": False, "error": None,
                              "facts": {}, "findings": [], "transcript": ""}
    if via_defaults:
        result["via_defaults"] = True
    if not ssh_available():
        result["error"] = ("no `ssh` binary found (Termux: `pkg install openssh`; "
                           "Windows: enable OpenSSH Client)")
        return result
    script = "; ".join(f"echo __BH_{name}__; {cmd}"
                       for name, cmd in READONLY_COMMANDS)
    cmd = _ssh_base(host, username, port, timeout) + [script]
    if password:
        if not sshpass_available():
            result["error"] = ("password login needs `sshpass` (or use key auth "
                               "with --shell ssh and no --password)")
            return result
        cmd = ["sshpass", "-p", password] + cmd
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 30)
    except subprocess.TimeoutExpired:
        result["error"] = "SSH command timed out"
        return result
    except OSError as exc:
        result["error"] = f"SSH exec failed: {exc}"
        return result
    if proc.returncode != 0 and not proc.stdout:
        err = proc.stderr.decode("utf-8", "replace")[-300:]
        result["error"] = f"SSH rejected/failed: {err.strip() or proc.returncode}"
        return result
    text = proc.stdout.decode("utf-8", "replace")
    outputs: Dict[str, str] = {}
    chunks = re.split(r"__BH_(\w+)__", text)
    for i in range(1, len(chunks) - 1, 2):
        outputs[chunks[i]] = chunks[i + 1].strip()

    # Reuse the Telnet fact/finding logic on identical command output.
    facts: Dict[str, Any] = {"commands": len(outputs)}
    m = re.search(r"uid=(\d+)\(([^)]+)\)", outputs.get("uid", ""))
    if m:
        facts["uid"] = int(m.group(1))
        facts["shell_user"] = m.group(2)
        facts["is_root"] = facts["uid"] == 0
    kernel = outputs.get("kernel", "")
    if kernel:
        facts["kernel"] = kernel.splitlines()[0][:160]
    parts = parse_mtd_table(outputs.get("mtd", ""))
    if parts:
        facts["mtd_partitions"] = parts
        facts["mtd_total_bytes"] = sum(p["size"] for p in parts)
    result["facts"] = facts
    result["ok"] = True
    result["transcript"] = redact_secrets(text[:60000])

    findings: List[Dict] = []
    if facts.get("is_root"):
        findings.append({
            "id": "SHELL-001",
            "title": "Credentialed SSH shell confirmed ROOT (uid=0)",
            "severity": SEV_HIGH if via_defaults else SEV_INFO,
            "confidence": "CONFIRMED",
            "cve": "N/A (administrative access)",
            "description": (f"SSH as '{username}' yielded uid=0. " +
                            ("Factory-default credentials — change them now."
                             if via_defaults else
                             "Expected admin path with owner credentials.")),
            "url": f"ssh://{host}/",
            "impact": "Full device control for credential holder.",
            "fix": ("Change password; prefer key auth." if via_defaults else
                    "No action."),
            "urls": [],
        })
    age = _kernel_age_note(kernel)
    if age:
        fid, sev, note = age
        findings.append({
            "id": fid, "title": "Ancient kernel on the live unit",
            "severity": sev, "confidence": "CONFIRMED",
            "cve": "N/A (patch-gap class)",
            "description": f"/proc/version: {kernel[:200]} {note}",
            "url": f"ssh://{host}/", "impact": "Unpatched kernel CVEs.",
            "fix": "Update firmware or bridge the unit.", "urls": [],
        })
    result["findings"] = findings
    return result


def dump_mtd_via_ssh(host: str, username: str, partition: str, outpath: str,
                     password: Optional[str] = None, port: int = 22,
                     timeout: int = 12, verbose: bool = False) -> Dict[str, Any]:
    res: Dict[str, Any] = {"ok": False, "error": None, "path": None,
                           "bytes": 0, "sha256": None, "method": "ssh+base64"}
    if not re.fullmatch(r"mtd\d+", partition):
        res["error"] = f"refusing suspicious partition name {partition!r}"
        return res
    if not ssh_available():
        res["error"] = "no `ssh` binary found"
        return res
    cmd = _ssh_base(host, username, port, timeout) + [f"base64 /dev/{partition}"]
    if password:
        if not sshpass_available():
            res["error"] = "password login needs `sshpass` or key auth"
            return res
        cmd = ["sshpass", "-p", password] + cmd
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=300)
    except subprocess.TimeoutExpired:
        res["error"] = "SSH dump timed out"
        return res
    except OSError as exc:
        res["error"] = f"SSH exec failed: {exc}"
        return res
    if proc.returncode != 0 or not proc.stdout:
        res["error"] = (proc.stderr.decode("utf-8", "replace")[-200:] or
                        "remote base64 failed (no base64? not root?)")
        return res
    try:
        raw = _decode_base64_blob(proc.stdout.decode("utf-8", "replace"))
    except (binascii.Error, ValueError) as exc:
        res["error"] = f"base64 decode failed: {exc}"
        return res
    with open(outpath, "wb") as fh:
        fh.write(raw)
    try:
        os.chmod(outpath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    res.update(ok=True, path=outpath, bytes=len(raw),
               sha256=hashlib.sha256(raw).hexdigest())
    return res


# --------------------------------------------------------------------------- #
# Artifact saving
# --------------------------------------------------------------------------- #

def save_shell_transcript(outdir: str, host: str, transport: str,
                          transcript: str) -> str:
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(outdir, f"shell_{transport}_{host.replace(':', '_')}_{stamp}.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(redact_secrets(transcript))
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path
