#!/usr/bin/env python3
"""Protocol-aware health checks for the public IP reference catalog."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import errno
import ipaddress
import json
import os
import random
import re
import socket
import struct
import subprocess
import time
from pathlib import Path


TIMEOUT_SECONDS = 3.0
NETWORK_UNAVAILABLE = {
    errno.EAFNOSUPPORT,
    errno.EADDRNOTAVAIL,
    errno.ENETDOWN,
    errno.ENETUNREACH,
}
IPV6_AVAILABLE = False


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def iso_jst(value: dt.datetime) -> str:
    jst = dt.timezone(dt.timedelta(hours=9), name="JST")
    return value.astimezone(jst).strftime("%Y-%m-%d %H:%M:%S JST")


def family_for(address: str) -> socket.AddressFamily:
    return socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET


def endpoint(address: str, port: int):
    return (address, port, 0, 0) if family_for(address) == socket.AF_INET6 else (address, port)


def qname_bytes(name: str) -> bytes:
    if name == ".":
        return b"\x00"
    labels = name.rstrip(".").split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"


def dns_check(address: str, root: bool = False) -> tuple[bool, float | None, str]:
    transaction_id = random.SystemRandom().randrange(0, 65536)
    flags = 0 if root else 0x0100
    qtype = 2 if root else 1  # NS for root, A for example.com
    query = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)
    query += qname_bytes("." if root else "example.com") + struct.pack("!HH", qtype, 1)
    started = time.perf_counter()
    try:
        with socket.socket(family_for(address), socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT_SECONDS)
            sock.connect(endpoint(address, 53))
            sock.send(query)
            response = sock.recv(4096)
    except OSError as exc:
        if exc.errno in NETWORK_UNAVAILABLE:
            return False, None, "network-unavailable"
        return False, None, exc.__class__.__name__.lower()
    latency = round((time.perf_counter() - started) * 1000, 1)
    return validate_dns(response, query, latency)


def validate_dns(response: bytes, query: bytes, latency: float):
    if len(response) < len(query):
        return False, latency, "short-response"
    transaction_id = struct.unpack("!H", query[:2])[0]
    response_id, response_flags, questions, answers, _, _ = struct.unpack("!HHHHHH", response[:12])
    rcode = response_flags & 0x000F
    if response_id != transaction_id or not (response_flags & 0x8000):
        return False, latency, "invalid-response"
    if rcode != 0:
        return False, latency, f"dns-rcode-{rcode}"
    if response_flags & 0x0200:
        return False, latency, "truncated-response"
    if questions != 1 or response[12:len(query)] != query[12:]:
        return False, latency, "question-mismatch"
    if answers == 0 or len(response) <= len(query):
        return False, latency, "empty-response"
    return True, latency, "dns-response"


def ntp_check(address: str) -> tuple[bool, float | None, str]:
    timestamp = time.time() + 2208988800
    tx_timestamp = struct.pack("!II", int(timestamp) & 0xffffffff, int((timestamp % 1) * 2**32))
    request = b"\x23" + (39 * b"\0") + tx_timestamp
    started = time.perf_counter()
    try:
        with socket.socket(family_for(address), socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT_SECONDS)
            sock.connect(endpoint(address, 123))
            sock.send(request)
            response = sock.recv(512)
    except OSError as exc:
        if exc.errno in NETWORK_UNAVAILABLE:
            return False, None, "network-unavailable"
        return False, None, exc.__class__.__name__.lower()
    latency = round((time.perf_counter() - started) * 1000, 1)
    return validate_ntp(response, tx_timestamp, latency)


def validate_ntp(response: bytes, tx_timestamp: bytes, latency: float):
    if len(response) < 48:
        return False, latency, "short-response"
    mode = response[0] & 0x07
    stratum = response[1]
    version = (response[0] >> 3) & 7
    leap = response[0] >> 6
    if mode != 4 or version not in (3, 4):
        return False, latency, "invalid-response"
    if response[24:32] != tx_timestamp:
        return False, latency, "origin-mismatch"
    if stratum == 0:
        return False, latency, "ntp-kiss-of-death"
    if leap == 3 or not 0 < stratum < 16 or response[40:48] == bytes(8):
        return False, latency, "ntp-unsynchronized"
    return True, latency, f"ntp-stratum-{stratum}"


def icmp_check(address: str) -> tuple[str, float | None]:
    command = ["ping", "-n", "-c", "1", "-W", "2"]
    if family_for(address) == socket.AF_INET6:
        command.append("-6")
    command.append(address)
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=4, check=False, env={**os.environ, "LC_ALL": "C"})
    except (FileNotFoundError, PermissionError):
        return "unsupported", None
    except subprocess.TimeoutExpired:
        return "down", None
    if completed.returncode == 0:
        match = re.search(r"time[=<]\s*([\d.]+)\s*ms", completed.stdout)
        return "up", float(match.group(1)) if match else None
    combined = f"{completed.stdout}\n{completed.stderr}".lower()
    if any(reason in combined for reason in ("network is unreachable", "address family not supported", "operation not permitted", "permission denied")):
        return "unsupported", None
    return "down", None


def check_target(target: dict) -> tuple[str, dict]:
    address = target["address"]
    checked_at = now_utc()
    method = target["method"]
    if family_for(address) == socket.AF_INET6 and not IPV6_AVAILABLE:
        protocol_ok, protocol_latency, detail = False, None, "ipv6-runner-unavailable"
    elif method == "dns-recursive":
        protocol_ok, protocol_latency, detail = dns_check(address)
    elif method == "dns-root":
        protocol_ok, protocol_latency, detail = dns_check(address, root=True)
    elif method == "ntp":
        protocol_ok, protocol_latency, detail = ntp_check(address)
    else:
        protocol_ok, protocol_latency, detail = False, None, "unsupported-method"

    skipped = detail in {"ipv6-runner-unavailable", "unsupported-method"}
    unavailable = skipped or detail == "network-unavailable"
    icmp_status, icmp_latency = ("unsupported", None) if skipped else icmp_check(address)
    if protocol_ok:
        status = "up"
    elif unavailable:
        status = "unknown"
    elif icmp_status == "up":
        status = "degraded"
    else:
        status = "down"

    return address, {
        "status": status,
        "protocolStatus": "up" if protocol_ok else "unknown" if unavailable else "down",
        "icmpStatus": icmp_status,
        "method": {"dns-recursive": "DNS UDP/53", "dns-root": "Root DNS UDP/53", "ntp": "NTP UDP/123"}.get(method, method),
        "latencyMs": protocol_latency,
        "icmpLatencyMs": icmp_latency,
        "checkedAt": None if skipped else iso_utc(checked_at),
        "checkedAtJst": None if skipped else iso_jst(checked_at),
        "attemptedAt": iso_utc(checked_at),
        "detail": detail,
    }


def ipv6_available() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.connect(("2001:4860:4860::8888", 53, 0, 0))
            return not ipaddress.ip_address(sock.getsockname()[0]).is_loopback
    except OSError:
        return False


def main() -> None:
    global IPV6_AVAILABLE
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", default="targets.json")
    parser.add_argument("--output", default="health.json")
    parser.add_argument("--workers", type=int, default=24)
    args = parser.parse_args()

    targets = json.loads(Path(args.targets).read_text(encoding="utf-8"))
    addresses = [target["address"] for target in targets]
    if not addresses or len(addresses) != len(set(addresses)):
        raise ValueError("Targets must be nonempty and unique")
    for target in targets:
        if not ipaddress.ip_address(target["address"]).is_global or target["method"] not in {"dns-recursive", "dns-root", "ntp"}:
            raise ValueError("Only cataloged public DNS/NTP addresses may be checked")
    IPV6_AVAILABLE = ipv6_available()
    started_at = now_utc()
    items: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(check_target, target) for target in targets]
        for future in concurrent.futures.as_completed(futures):
            address, result = future.result()
            items[address] = result

    counts = {name: sum(item["status"] == name for item in items.values()) for name in ("up", "degraded", "down", "unknown")}
    finished_at = now_utc()
    payload = {
        "schemaVersion": 1,
        "generatedAt": iso_utc(finished_at),
        "generatedAtJst": iso_jst(finished_at),
        "durationSeconds": round((finished_at - started_at).total_seconds(), 1),
        "summary": {"total": len(items), **counts},
        "runner": {"provider": "GitHub Actions", "ipv6Available": IPV6_AVAILABLE},
        "items": dict(sorted(items.items())),
    }
    output = Path(args.output)
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(json.dumps(payload["summary"], ensure_ascii=False))

if __name__ == "__main__":
    main()
