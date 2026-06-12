from __future__ import annotations

import base64
import ctypes
import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / ".clearguard"
QUARANTINE_DIR = DATA_DIR / "quarantine"
CONFIG_PATH = DATA_DIR / "config.json"
ACTIVITY_PATH = DATA_DIR / "activity.jsonl"
SEEN_PATH = DATA_DIR / "seen_files.json"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_SCAN_FILES = 1200
MONITOR_INTERVAL_SECONDS = 8
MONITOR_PASS_LIMIT = 350
MONITOR_STARTED = False

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SCRIPT_PATTERNS = [
    (re.compile(rb"powershell(\.exe)?\s+(-enc|-encodedcommand)", re.I), "Encoded PowerShell command"),
    (re.compile(rb"invoke-webrequest|downloadstring|start-bitstransfer", re.I), "Script downloads remote code"),
    (re.compile(rb"certutil(\.exe)?\s+(-decode|-urlcache)", re.I), "Certificate utility used for payload staging"),
    (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.I), "Deletes backup snapshots"),
    (re.compile(rb"set-mppreference\s+-disablerealtimemonitoring", re.I), "Attempts to disable Windows Defender"),
    (re.compile(rb"rundll32(\.exe)?\s+.*javascript:", re.I), "Rundll32 JavaScript execution"),
    (re.compile(rb"mshta(\.exe)?\s+https?://", re.I), "MSHTA remote script execution"),
]
SELF_SCAN_FILES = {"server.py", "app.js", "index.html", "styles.css", "README.md"}
SUSPICIOUS_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".docm",
    ".exe",
    ".hta",
    ".jar",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbe",
    ".vbs",
    ".wsf",
}
HIGH_RISK_PROCESS_NAMES = {
    "bitsadmin",
    "certutil",
    "cmd",
    "cscript",
    "mshta",
    "powershell",
    "pwsh",
    "regsvr32",
    "rundll32",
    "wscript",
}
COMMON_INTERNET_PROCESS_NAMES = {
    "chrome",
    "firefox",
    "msedge",
    "onedrive",
    "outlook",
    "teams",
    "discord",
    "spotify",
    "steam",
    "explorer",
    "applicationframehost",
    "backgroundtaskhost",
    "searchhost",
    "shellexperiencehost",
    "startmenuexperiencehost",
    "widgetservice",
    "widgets",
    "runtimebroker",
}
REVERSE_DNS_CACHE: dict[str, str | None] = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    QUARANTINE_DIR.mkdir(exist_ok=True)
    if not CONFIG_PATH.exists():
        save_config(
            {
                "mode": "balanced",
                "protected_paths": default_scan_paths(),
                "rules": built_in_rules(),
                "last_scan": None,
                "realtime_enabled": True,
                "notifications_enabled": True,
            }
        )


def default_scan_paths() -> list[str]:
    home = Path.home()
    candidates = [home / "Downloads", home / "Desktop", home / "Documents"]
    return [str(path) for path in candidates if path.exists()]


def built_in_rules() -> list[dict[str, str]]:
    return [
        {
            "name": "Antivirus test signature",
            "plain": "Quarantine any file containing the EICAR antivirus test string.",
            "action": "quarantine",
        },
        {
            "name": "Script payload chain",
            "plain": "Flag scripts that download remote code, run encoded commands, or disable recovery.",
            "action": "alert",
        },
        {
            "name": "Risky launch locations",
            "plain": "Raise risk for executables, scripts, and shortcuts in user-writable folders.",
            "action": "alert",
        },
        {
            "name": "Suspicious outbound tools",
            "plain": "Flag internet connections made by shell, script, and Windows living-off-the-land tools.",
            "action": "alert",
        },
    ]


def load_config() -> dict[str, Any]:
    ensure_dirs()
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    changed = False
    defaults = {
        "mode": "balanced",
        "protected_paths": default_scan_paths(),
        "rules": built_in_rules(),
        "last_scan": None,
        "realtime_enabled": True,
        "notifications_enabled": True,
    }
    for key, value in defaults.items():
        if key not in config:
            config[key] = value
            changed = True
    if changed:
        save_config(config)
    return config


def save_config(config: dict[str, Any]) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")


def log_activity(kind: str, title: str, detail: str, risk: str = "low", extra: dict[str, Any] | None = None) -> None:
    ensure_dirs()
    event = {
        "time": now_iso(),
        "kind": kind,
        "title": title,
        "detail": detail,
        "risk": risk,
        "extra": extra or {},
    }
    with ACTIVITY_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def notify_user(title: str, message: str, risk: str = "medium") -> None:
    try:
        if not load_config().get("notifications_enabled", True):
            return
        if risk_rank(risk) < risk_rank("high"):
            return
        safe_title = title.replace("'", "''")[:80]
        safe_message = message.replace("'", "''")[:260]
        script = f"$ws=New-Object -ComObject WScript.Shell; $null=$ws.Popup('{safe_message}', 8, '{safe_title}', 48)"
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def recent_activity(limit: int = 50) -> list[dict[str, Any]]:
    ensure_dirs()
    if not ACTIVITY_PATH.exists():
        return []
    lines = ACTIVITY_PATH.read_text(encoding="utf-8").splitlines()
    events = []
    for line in lines[-limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(events))


def read_head(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    value = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            value -= p * math.log2(p)
    return round(value, 2)


def risk_rank(risk: str) -> int:
    return {"clean": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(risk, 1)


def scan_file(path: Path) -> dict[str, Any]:
    result = {
        "path": str(path),
        "name": path.name,
        "size": 0,
        "sha256": None,
        "risk": "clean",
        "findings": [],
        "scanned_at": now_iso(),
    }
    try:
        if is_clearguard_program_file(path):
            result["risk"] = "low"
            result["findings"].append("ClearGuard program file skipped by self-protection policy.")
            return result

        stat = path.stat()
        result["size"] = stat.st_size
        if not path.is_file():
            result["risk"] = "low"
            result["findings"].append("Skipped because it is not a regular file.")
            return result
        if stat.st_size > MAX_FILE_BYTES:
            result["risk"] = "medium"
            result["findings"].append(f"Skipped full content scan because file is larger than {MAX_FILE_BYTES // 1024 // 1024} MB.")
            return result
        data = read_head(path)
        ext = path.suffix.lower()
        sample_entropy = entropy(data[:1024 * 1024])
        result["sha256"] = sha256_file(path)
        dependency_file = is_dependency_file(path)

        if EICAR in data:
            result["risk"] = "critical"
            result["findings"].append("Matched EICAR antivirus test signature.")

        if ext in SUSPICIOUS_EXTENSIONS and not dependency_file:
            result["risk"] = max(result["risk"], "medium", key=risk_rank)
            result["findings"].append(f"{ext} is an executable or script-like file type.")
        elif dependency_file:
            result["risk"] = max(result["risk"], "low", key=risk_rank)
            result["findings"].append("Dependency/package file; not suspicious by file type alone.")

        user_writable_markers = ["\\downloads\\", "\\appdata\\local\\temp\\", "\\desktop\\"]
        lower_path = str(path).lower()
        if ext in SUSPICIOUS_EXTENSIONS and not dependency_file and any(marker in lower_path for marker in user_writable_markers):
            result["risk"] = max(result["risk"], "high", key=risk_rank)
            result["findings"].append("Executable or script is in a common user-writable launch location.")

        for pattern, finding in SCRIPT_PATTERNS:
            if pattern.search(data):
                result["risk"] = max(result["risk"], "high", key=risk_rank)
                result["findings"].append(finding)

        if ext in {".exe", ".dll", ".scr"} and sample_entropy >= 7.4:
            result["risk"] = max(result["risk"], "medium", key=risk_rank)
            result["findings"].append(f"High byte entropy ({sample_entropy}) can indicate packing or compression.")

        if not result["findings"]:
            result["findings"].append("No local signatures or risky behaviors matched.")
        return result
    except PermissionError:
        result["risk"] = "medium"
        result["findings"].append("Permission denied while scanning this file.")
        return result
    except OSError as exc:
        result["risk"] = "medium"
        result["findings"].append(f"Could not scan file: {exc}")
        return result


def is_clearguard_program_file(path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(ROOT)
    except ValueError:
        return False
    if relative.parts and relative.parts[0] in {".clearguard", "__pycache__"}:
        return True
    return len(relative.parts) == 1 and relative.name in SELF_SCAN_FILES


def is_dependency_file(path: Path) -> bool:
    dependency_dirs = {"node_modules", ".venv", "venv", "site-packages", "__pycache__"}
    parts = {part.lower() for part in path.parts}
    return bool(parts & dependency_dirs)


def scan_path(target: str) -> dict[str, Any]:
    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise ValueError("Path does not exist.")

    start = time.time()
    files: list[Path]
    if path.is_file():
        files = [path]
    else:
        files = []
        for root, _, names in os.walk(path):
            for name in names:
                files.append(Path(root) / name)
                if len(files) >= MAX_SCAN_FILES:
                    break
            if len(files) >= MAX_SCAN_FILES:
                break

    results = [scan_file(file_path) for file_path in files]
    counts = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for result in results:
        counts[result["risk"]] = counts.get(result["risk"], 0) + 1
    risky = [item for item in results if risk_rank(item["risk"]) >= 2]
    summary = {
        "target": str(path),
        "started_at": now_iso(),
        "duration_seconds": round(time.time() - start, 2),
        "file_count": len(results),
        "truncated": len(files) >= MAX_SCAN_FILES,
        "counts": counts,
        "risky": risky[:100],
    }
    config = load_config()
    config["last_scan"] = summary
    save_config(config)
    worst = max(counts, key=lambda key: risk_rank(key) if counts[key] else -1)
    log_activity(
        "scan",
        f"Scanned {summary['file_count']} file(s)",
        f"{len(risky)} item(s) need review in {summary['target']}.",
        "high" if risk_rank(worst) >= 3 else "medium" if risky else "low",
        {"target": summary["target"], "counts": counts},
    )
    if risky and risk_rank(worst) >= 3:
        notify_user("ClearGuard warning", f"{len(risky)} risky file(s) found in {summary['target']}.", worst)
    return summary


def load_seen_files() -> dict[str, float]:
    if not SEEN_PATH.exists():
        return {}
    try:
        return json.loads(SEEN_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_seen_files(seen: dict[str, float]) -> None:
    SEEN_PATH.write_text(json.dumps(seen), encoding="utf-8")


def monitored_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw_path in paths:
        root = Path(raw_path).expanduser()
        if not root.exists():
            continue
        if root.is_file():
            files.append(root)
            continue
        for current_root, dirs, names in os.walk(root):
            dirs[:] = [name for name in dirs if name.lower() not in {"node_modules", ".git", ".venv", "venv", "__pycache__"}]
            for name in names:
                files.append(Path(current_root) / name)
                if len(files) >= MONITOR_PASS_LIMIT:
                    return files
    return files


def monitor_once() -> None:
    config = load_config()
    if not config.get("realtime_enabled", True):
        return
    seen = load_seen_files()
    changed = False
    files = monitored_files(config.get("protected_paths", []))
    if not SEEN_PATH.exists():
        for path in files:
            try:
                seen[str(path.resolve())] = path.stat().st_mtime
            except OSError:
                continue
        save_seen_files(dict(list(seen.items())[-5000:]))
        log_activity("realtime", "Realtime monitor baseline created", f"Watching {len(seen)} existing file(s) for future changes.", "low")
        return
    for path in files:
        try:
            stat = path.stat()
        except OSError:
            continue
        key = str(path.resolve())
        fingerprint = stat.st_mtime
        if seen.get(key) == fingerprint:
            continue
        seen[key] = fingerprint
        changed = True
        result = scan_file(path)
        if risk_rank(result["risk"]) >= risk_rank("high"):
            detail = "; ".join(result["findings"])
            log_activity("realtime", f"Risky file changed: {path.name}", detail, result["risk"], {"path": str(path)})
            notify_user("ClearGuard blocked a risky-looking download", f"{path.name}: {detail}", result["risk"])
    if changed:
        save_seen_files(dict(list(seen.items())[-5000:]))


def monitor_loop() -> None:
    while True:
        try:
            monitor_once()
        except Exception as exc:
            log_activity("realtime", "Realtime monitor error", str(exc), "medium")
        time.sleep(MONITOR_INTERVAL_SECONDS)


def start_monitor() -> None:
    global MONITOR_STARTED
    if MONITOR_STARTED:
        return
    MONITOR_STARTED = True
    threading.Thread(target=monitor_loop, name="ClearGuardRealtimeMonitor", daemon=True).start()


def quarantine_index_path() -> Path:
    return DATA_DIR / "quarantine.json"


def load_quarantine() -> list[dict[str, Any]]:
    ensure_dirs()
    path = quarantine_index_path()
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save_quarantine(items: list[dict[str, Any]]) -> None:
    quarantine_index_path().write_text(json.dumps(items, indent=2), encoding="utf-8")


def quarantine_file(target: str, reason: str | None = None) -> dict[str, Any]:
    path = Path(target).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise ValueError("Only existing files can be quarantined.")
    scan = scan_file(path)
    file_hash = scan["sha256"] or sha256_file(path)
    quarantine_name = f"{int(time.time())}_{file_hash[:12]}_{path.name}"
    quarantine_path = QUARANTINE_DIR / quarantine_name
    shutil.move(str(path), str(quarantine_path))
    item = {
        "id": file_hash[:16] + "-" + str(int(time.time())),
        "name": path.name,
        "original_path": str(path),
        "quarantine_path": str(quarantine_path),
        "sha256": file_hash,
        "reason": reason or "; ".join(scan["findings"]),
        "risk": scan["risk"],
        "status": "contained",
        "created_at": now_iso(),
    }
    items = load_quarantine()
    items.insert(0, item)
    save_quarantine(items)
    log_activity("quarantine", f"Quarantined {path.name}", item["reason"], item["risk"], {"sha256": file_hash})
    return item


def update_quarantine(item_id: str, action: str) -> dict[str, Any]:
    items = load_quarantine()
    for item in items:
        if item["id"] != item_id:
            continue
        quarantine_path = Path(item["quarantine_path"])
        if action == "delete":
            if quarantine_path.exists():
                quarantine_path.unlink()
            item["status"] = "deleted"
            log_activity("quarantine", f"Deleted {item['name']} from quarantine", item["reason"], item["risk"])
        elif action == "restore":
            original_path = Path(item["original_path"])
            if original_path.exists():
                raise ValueError("Original path already exists. Restore manually from quarantine.")
            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(quarantine_path), str(original_path))
            item["status"] = "restored"
            log_activity("quarantine", f"Restored {item['name']}", item["original_path"], "medium")
        else:
            raise ValueError("Unknown quarantine action.")
        save_quarantine(items)
        return item
    raise ValueError("Quarantine item not found.")


def powershell_json(script: str, timeout: int = 8) -> Any:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "PowerShell command failed.")
    output = completed.stdout.strip()
    if not output:
        return []
    data = json.loads(output)
    return data if isinstance(data, list) else [data]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def persistence_installed() -> bool:
    completed = subprocess.run(
        ["schtasks", "/Query", "/TN", "ClearGuard AV Agent"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return completed.returncode == 0


def reverse_dns(remote_address: str) -> str | None:
    address = remote_address.split("%")[0]
    if address in REVERSE_DNS_CACHE:
        return REVERSE_DNS_CACHE[address]
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(0.35)
    try:
        host = socket.gethostbyaddr(address)[0].rstrip(".")
    except Exception:
        host = None
    finally:
        socket.setdefaulttimeout(previous_timeout)
    REVERSE_DNS_CACHE[address] = host
    return host


def service_hint(process: str, remote_address: str, port: Any, host: str | None) -> str:
    lower_process = process.lower()
    lower_host = (host or "").lower()
    provider = provider_hint(remote_address)
    if provider:
        return provider
    if "1e100.net" in lower_host or "google" in lower_host or str(port) == "5228":
        return "Likely Google service used by browser sync, push notifications, search, or web pages."
    if "cloudflare" in lower_host:
        return "Likely Cloudflare, a common web/CDN provider used by many sites."
    if "microsoft" in lower_host or "msn" in lower_host or "live" in lower_host:
        return "Likely Microsoft service used by Windows, Edge, OneDrive, Office, or account features."
    if "amazonaws" in lower_host or "cloudfront" in lower_host:
        return "Likely AWS or CloudFront hosting used by an app or website."
    if lower_process in {"chrome", "firefox", "msedge"} and str(port) in {"443", "80", "5228"}:
        return "Browser web traffic. This is usually a tab, extension, sync, notification, or background web service."
    if lower_process == "explorer":
        return "Windows shell traffic. This can be OneDrive, Microsoft account, search, widgets, or file integration."
    return "No familiar service label found locally."


def provider_hint(remote_address: str) -> str | None:
    try:
        ip = ipaddress.ip_address(remote_address.split("%")[0])
    except ValueError:
        return None
    ranges = [
        ("Google", ["142.250.0.0/15", "74.125.0.0/16", "216.239.32.0/19", "172.217.0.0/16", "172.253.0.0/16"]),
        ("Cloudflare", ["172.64.0.0/13", "104.16.0.0/12", "1.1.1.0/24"]),
        ("Microsoft", ["52.96.0.0/12", "52.112.0.0/14", "52.120.0.0/14", "20.0.0.0/8", "40.64.0.0/10"]),
    ]
    for provider, cidrs in ranges:
        if any(ip in ipaddress.ip_network(cidr) for cidr in cidrs):
            return f"Likely {provider} infrastructure. This can support normal browser, Windows, cloud, or app traffic."
    return None


def connection_explanation(process: str, remote: str, port: Any, enrich: bool = True) -> dict[str, Any]:
    lower_process = process.lower()
    quick_provider = provider_hint(remote)
    host = None
    findings = []
    risk = "low"
    try:
        ip = ipaddress.ip_address(remote.split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            findings.append("Local or private network connection.")
            risk = "info"
        elif lower_process in HIGH_RISK_PROCESS_NAMES:
            risk = "high"
            findings.append(f"{process} is a command/script tool that malware commonly abuses for outbound traffic.")
        elif lower_process in COMMON_INTERNET_PROCESS_NAMES:
            risk = "info"
            findings.append("Common app internet traffic; not suspicious by itself.")
        else:
            risk = "medium"
            findings.append("Unknown or less common app connected to a public internet address.")
    except ValueError:
        findings.append("Remote address could not be classified.")

    hint = service_hint(process, remote, port, host)
    if host:
        findings.append(f"Reverse DNS: {host}.")
    findings.append(hint)
    return {"risk": risk, "host": host, "service_hint": hint, "findings": findings}


def network_connections(enrich: bool = True) -> list[dict[str, Any]]:
    script = r"""
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
      Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1') } |
      Select-Object -First 250 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
    $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
    $proc = @{}
    foreach ($procId in $pids) {
      try {
        $p = Get-Process -Id $procId -ErrorAction Stop
        $proc[$procId] = [PSCustomObject]@{ Name=$p.ProcessName; Path=$p.Path }
      } catch {
        $proc[$procId] = [PSCustomObject]@{ Name='Unknown'; Path=$null }
      }
    }
    $conns | ForEach-Object {
      [PSCustomObject]@{
        LocalAddress=$_.LocalAddress
        LocalPort=$_.LocalPort
        RemoteAddress=$_.RemoteAddress
        RemotePort=$_.RemotePort
        State=$_.State
        PID=$_.OwningProcess
        ProcessName=$proc[$_.OwningProcess].Name
        ProcessPath=$proc[$_.OwningProcess].Path
      }
    } | ConvertTo-Json -Depth 4
    """
    try:
        rows = powershell_json(script)
    except Exception as exc:
        log_activity("network", "Could not read TCP connections", str(exc), "medium")
        return []

    results = []
    for row in rows:
        remote = str(row.get("RemoteAddress") or "")
        process = str(row.get("ProcessName") or "Unknown")
        explanation = connection_explanation(process, remote, row.get("RemotePort"), enrich=enrich)

        results.append(
            {
                "local": f"{row.get('LocalAddress')}:{row.get('LocalPort')}",
                "remote": f"{remote}:{row.get('RemotePort')}",
                "remote_address": remote,
                "remote_port": row.get("RemotePort"),
                "state": row.get("State"),
                "pid": row.get("PID"),
                "process": process,
                "path": row.get("ProcessPath"),
                "risk": explanation["risk"],
                "host": explanation["host"],
                "service_hint": explanation["service_hint"],
                "findings": explanation["findings"],
            }
        )
    return sorted(results, key=lambda item: risk_rank(item["risk"]), reverse=True)


def block_ip(remote_address: str) -> dict[str, Any]:
    ipaddress.ip_address(remote_address.split("%")[0])
    rule_name = f"ClearGuard Block {remote_address}"
    if not is_admin():
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={remote_address}'
        raise PermissionError(f"Blocking requires administrator rights. Restart ClearGuard as Administrator or run this in an elevated PowerShell: {command}")
    completed = subprocess.run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={remote_address}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "Firewall rule failed.")
    log_activity("network", f"Blocked outbound traffic to {remote_address}", rule_name, "medium")
    return {"remote_address": remote_address, "rule": rule_name, "output": completed.stdout.strip()}


def unblock_rule(rule_name: str) -> dict[str, Any]:
    if not rule_name:
        raise ValueError("Firewall rule name is required.")
    if not is_admin():
        command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        raise PermissionError(f"Unblocking requires administrator rights. Restart ClearGuard as Administrator or run this in an elevated PowerShell: {command}")
    completed = subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "Firewall unblock failed.")
    log_activity("network", f"Removed firewall block rule", rule_name, "medium")
    return {"rule": rule_name, "output": completed.stdout.strip()}


def blocked_ips() -> list[dict[str, Any]]:
    script = r"""
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
      Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' -and $_.Enabled -eq 'True' } |
      Select-Object -First 200
    $items = @()
    foreach ($rule in $rules) {
      $address = $rule | Get-NetFirewallAddressFilter
      if ($address.RemoteAddress -and $address.RemoteAddress -notin @('Any','LocalSubnet','Internet','Intranet','DefaultGateway','DNS','DHCP','WINS')) {
      $remoteText = [string]::Join(', ', @($address.RemoteAddress))
      $items += [PSCustomObject]@{
        Name=$rule.DisplayName
        Enabled=$rule.Enabled.ToString()
        Direction=$rule.Direction.ToString()
        Action=$rule.Action.ToString()
        RemoteAddress=$remoteText
      }
      }
    }
    $items | ConvertTo-Json -Depth 4
    """
    try:
        rows = powershell_json(script)
    except Exception as exc:
        log_activity("network", "Could not read ClearGuard firewall rules", str(exc), "medium")
        return []
    results = []
    for row in rows:
        remote = row.get("RemoteAddress")
        if isinstance(remote, list):
            remote_text = ", ".join(str(item) for item in remote)
        else:
            remote_text = str(remote or "")
        results.append(
            {
                "name": row.get("Name"),
                "enabled": row.get("Enabled"),
                "direction": row.get("Direction"),
                "action": row.get("Action"),
                "remote_address": remote_text,
            }
        )
    return results


def investigate_url(raw_url: str) -> dict[str, Any]:
    if not raw_url:
        raise ValueError("URL is required.")
    parsed = urllib.parse.urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only http and https URLs are supported.")
    host = parsed.hostname
    findings = []
    risk = "low"
    if parsed.scheme == "http":
        risk = "medium"
        findings.append("Site uses unencrypted HTTP.")
    if "@" in raw_url:
        risk = "high"
        findings.append("URL contains @, which can hide the real destination.")
    if len(host) > 60 or host.count("-") >= 4:
        risk = max(risk, "medium", key=risk_rank)
        findings.append("Hostname shape is unusual.")
    try:
        ascii_host = host.encode("idna").decode("ascii")
        if ascii_host != host:
            risk = max(risk, "medium", key=risk_rank)
            findings.append("Hostname uses internationalized characters; verify it is not a lookalike.")
    except UnicodeError:
        risk = "high"
        findings.append("Hostname encoding is unusual.")

    addresses = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            address = sockaddr[0]
            if address not in addresses:
                addresses.append(address)
            ip = ipaddress.ip_address(address)
            if ip.is_private or ip.is_loopback:
                risk = max(risk, "medium", key=risk_rank)
                findings.append("Domain resolves to a private or local address.")
    except OSError as exc:
        risk = max(risk, "medium", key=risk_rank)
        findings.append(f"DNS lookup failed: {exc}")

    if not findings:
        findings.append("No obvious local URL red flags found. This is not a reputation verdict.")
    result = {"url": urllib.parse.urlunparse(parsed), "host": host, "addresses": addresses, "risk": risk, "findings": findings}
    log_activity("investigation", f"Checked {host}", "; ".join(findings), risk)
    return result


def status() -> dict[str, Any]:
    config = load_config()
    network = network_connections(enrich=False)
    high_network = sum(1 for item in network if item["risk"] == "high")
    medium_network = sum(1 for item in network if item["risk"] == "medium")
    quarantine = load_quarantine()
    contained = sum(1 for item in quarantine if item["status"] == "contained")
    last_scan = config.get("last_scan")
    last_scan_summary = None
    risky_files = 0
    if last_scan:
        counts = last_scan.get("counts", {})
        risky_files = counts.get("medium", 0) + counts.get("high", 0) + counts.get("critical", 0)
        last_scan_summary = {
            "target": last_scan.get("target"),
            "started_at": last_scan.get("started_at"),
            "duration_seconds": last_scan.get("duration_seconds"),
            "file_count": last_scan.get("file_count"),
            "truncated": last_scan.get("truncated"),
            "counts": counts,
            "risky_count": risky_files,
        }
    ordinary_public_connections = min(medium_network, 10)
    score = max(0, 100 - contained * 6 - min(risky_files, 20) * 2 - high_network * 10 - ordinary_public_connections)
    return {
        "mode": config.get("mode", "balanced"),
        "trust_score": score,
        "protected_paths": config.get("protected_paths", []),
        "last_scan": last_scan_summary,
        "quarantine_count": contained,
        "network_count": len(network),
        "high_network_count": high_network,
        "is_admin": is_admin(),
        "blocked_ip_count": len(blocked_ips()),
        "realtime_enabled": config.get("realtime_enabled", True),
        "notifications_enabled": config.get("notifications_enabled", True),
        "persistence_installed": persistence_installed(),
        "rules": config.get("rules", []),
        "activity": recent_activity(8),
    }


def json_response(handler: SimpleHTTPRequestHandler, payload: Any, status_code: int = 200) -> None:
    data = json.dumps(payload).encode("utf-8")
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def read_json(handler: SimpleHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return {}
    return json.loads(handler.rfile.read(length).decode("utf-8"))


class ClearGuardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self) -> None:
        try:
            if self.path in {"/", "/index.html"}:
                self.send_response(302)
                self.send_header("Location", "/console.html")
                self.end_headers()
            elif self.path == "/api/status":
                json_response(self, status())
            elif self.path == "/api/activity":
                json_response(self, recent_activity(50))
            elif self.path == "/api/quarantine":
                json_response(self, load_quarantine())
            elif self.path == "/api/network":
                json_response(self, network_connections())
            elif self.path == "/api/blocked-ips":
                json_response(self, blocked_ips())
            elif self.path == "/api/rules":
                json_response(self, load_config().get("rules", []))
            else:
                super().do_GET()
        except Exception as exc:
            json_response(self, {"error": str(exc)}, 500)

    def do_POST(self) -> None:
        try:
            body = read_json(self)
            if self.path == "/api/scan":
                target = body.get("path")
                if not target:
                    paths = load_config().get("protected_paths", [])
                    if not paths:
                        raise ValueError("No default protected paths found.")
                    target = paths[0]
                json_response(self, scan_path(str(target)))
            elif self.path == "/api/quarantine":
                json_response(self, quarantine_file(str(body.get("path", "")), body.get("reason")))
            elif self.path.startswith("/api/quarantine/"):
                item_id = urllib.parse.unquote(self.path.rsplit("/", 1)[-1])
                json_response(self, update_quarantine(item_id, str(body.get("action", ""))))
            elif self.path == "/api/settings":
                config = load_config()
                mode = body.get("mode")
                if mode in {"quiet", "balanced", "strict"}:
                    config["mode"] = mode
                    save_config(config)
                    log_activity("settings", f"Protection mode changed to {mode}", "User updated local policy.", "low")
                for key in ("realtime_enabled", "notifications_enabled"):
                    if key in body:
                        config[key] = bool(body[key])
                        save_config(config)
                        label = key.replace("_", " ")
                        log_activity("settings", f"{label} {'enabled' if config[key] else 'disabled'}", "User updated local policy.", "low")
                json_response(self, config)
            elif self.path == "/api/block-ip":
                json_response(self, block_ip(str(body.get("remote_address", ""))))
            elif self.path == "/api/unblock-ip":
                json_response(self, unblock_rule(str(body.get("rule_name", ""))))
            elif self.path == "/api/investigate-url":
                json_response(self, investigate_url(str(body.get("url", ""))))
            elif self.path == "/api/test-notification":
                notify_user("ClearGuard test alert", "Laptop notifications are enabled.", "high")
                json_response(self, {"ok": True})
            else:
                json_response(self, {"error": "Not found"}, 404)
        except Exception as exc:
            json_response(self, {"error": str(exc)}, 400)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}")


def main() -> None:
    ensure_dirs()
    start_monitor()
    port = int(os.environ.get("CLEARGUARD_PORT", "5288"))
    server = ThreadingHTTPServer(("127.0.0.1", port), ClearGuardHandler)
    print(f"ClearGuard running at http://127.0.0.1:{port}/console.html")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping ClearGuard.")


if __name__ == "__main__":
    main()
