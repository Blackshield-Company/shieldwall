import re
from dataclasses import dataclass
from pathlib import Path

from shieldwall.commands import SS_ARGV
from shieldwall.config import Allowlist
from shieldwall.model import Plate, unknown_plate
from shieldwall.runner import access_denied

PROC_PATHS = {
    "tcp": "/proc/net/tcp",
    "tcp6": "/proc/net/tcp6",
    "udp": "/proc/net/udp",
    "udp6": "/proc/net/udp6",
}

_PROCESS = re.compile(r'\(\("([^"]+)"')


@dataclass
class Listener:
    proto: str
    port: int
    bind: str
    process: str = ""


def split_addr(local: str) -> tuple[str, int]:
    if local.startswith("["):
        host, _, port = local[1:].rpartition("]:")
        return host, int(port)
    if "% " in local:
        local = local.split("%", 1)[0]
    host, sep, port = local.rpartition(":")
    if not sep:
        raise ValueError(f"bad address: {local}")
    if "%" in host:
        host = host.split("%", 1)[0]
    return host, int(port)


def parse_ss(text: str) -> list[Listener]:
    found: list[Listener] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("netid"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto_raw = parts[0].lower()
        state = parts[1].upper()
        if proto_raw.startswith("tcp"):
            proto = "tcp"
            if state != "LISTEN":
                continue
        elif proto_raw.startswith("udp"):
            proto = "udp"
        else:
            continue
        try:
            host, port = split_addr(parts[4])
        except ValueError:
            continue
        process = ""
        if len(parts) > 5:
            match = _PROCESS.search(" ".join(parts[5:]))
            if match:
                process = match.group(1)
        found.append(Listener(proto=proto, port=port, bind=host, process=process))
    return found


def decode_proc_ip(hexip: str) -> str:
    if len(hexip) == 8:
        raw = bytes.fromhex(hexip)[::-1]
        return ".".join(str(byte) for byte in raw)
    if len(hexip) == 32:
        chunks = []
        for index in range(0, 32, 8):
            chunks.append(bytes.fromhex(hexip[index : index + 8])[::-1])
        import ipaddress

        return str(ipaddress.IPv6Address(b"".join(chunks)))
    raise ValueError(f"bad proc address: {hexip}")


def parse_proc_net(text: str, kind: str) -> list[Listener]:
    base = "tcp" if kind.startswith("tcp") else "udp"
    found: list[Listener] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("sl"):
            continue
        parts = line.split()
        if len(parts) < 4 or ":" not in parts[1]:
            continue
        local, state = parts[1], parts[3].upper()
        if base == "tcp" and state != "0A":
            continue
        if base == "udp" and state != "07":
            continue
        ip_hex, port_hex = local.split(":")
        try:
            host = decode_proc_ip(ip_hex)
            port = int(port_hex, 16)
        except ValueError:
            continue
        found.append(Listener(proto=base, port=port, bind=host, process=""))
    return found


def read_proc_files() -> dict[str, str | None]:
    found = False
    out: dict[str, str | None] = {}
    for name, path in PROC_PATHS.items():
        try:
            out[name] = Path(path).read_text(encoding="utf-8", errors="replace")
            found = True
        except OSError:
            out[name] = None
    if not found:
        return {}
    return out


def dedupe_listeners(listeners: list[Listener]) -> list[Listener]:
    order: list[tuple[str, int]] = []
    by_key: dict[tuple[str, int], Listener] = {}
    for item in listeners:
        key = (item.proto, item.port)
        if key not in by_key:
            by_key[key] = item
            order.append(key)
        elif not by_key[key].process and item.process:
            by_key[key] = item
    return [by_key[key] for key in order]


def plate_from_listeners(listeners: list[Listener], allowlist: Allowlist, source: str) -> Plate:
    unique = dedupe_listeners(listeners)
    unexpected = [item for item in unique if not allowlist.allows(item.proto, item.port)]
    if unexpected:
        status = "broken"
        detail = f":{unexpected[0].port} ?"
    elif unique:
        status = "intact"
        proc = unique[0].process or "ok"
        detail = f":{unique[0].port} {proc}"
    else:
        status = "intact"
        detail = "none"
    evidence: list[str] = []
    if not allowlist.configured and unique:
        evidence.append("no allowlist configured; every listener is unexpected")
    for item in unique:
        flag = "allow" if allowlist.allows(item.proto, item.port) else "not in allowlist"
        proc = item.process or "-"
        evidence.append(f"{item.proto} :{item.port} {item.bind} {proc} {flag}")
    if not unique:
        evidence.append(f"no listening sockets ({source})")
    evidence.append(f"source: {source}")
    return Plate(
        name="ports",
        status=status,
        headline=f"{len(unique)} listen",
        detail=detail,
        evidence=evidence,
    )


def collect_ports(runner, allowlist: Allowlist | None = None, proc_reader=None) -> Plate:
    allowlist = allowlist if allowlist is not None else Allowlist()
    ss = runner.run(SS_ARGV)
    ss_error = None
    if ss.not_found:
        ss_error = "ss not found"
    elif ss.timed_out:
        ss_error = "ss timed out"
    elif access_denied(ss) and not (ss.stdout or "").strip():
        ss_error = "ss: permission denied"
    elif ss.returncode == 0:
        return plate_from_listeners(parse_ss(ss.stdout), allowlist, "ss")
    elif ss.returncode is not None:
        ss_error = f"ss exited {ss.returncode}"
    else:
        ss_error = "ss failed"

    reader = proc_reader or read_proc_files
    try:
        files = reader()
    except OSError as exc:
        return unknown_plate("ports", ss_error or str(exc), "no sockets")
    if not files:
        return unknown_plate("ports", ss_error or "ss missing and /proc/net unreadable", "no sockets")
    listeners: list[Listener] = []
    any_text = False
    for name, text in files.items():
        if not text:
            continue
        any_text = True
        listeners.extend(parse_proc_net(text, name))
    if not any_text:
        return unknown_plate("ports", ss_error or "/proc/net unreadable", "no sockets")
    return plate_from_listeners(listeners, allowlist, "proc")
