import re
from dataclasses import dataclass
from pathlib import Path

from shieldwall.commands import AUTH_LOG_PATHS, JOURNAL_UNITS, journal_argv
from shieldwall.model import Plate, unknown_plate
from shieldwall.runner import access_denied

_ACCEPTED = re.compile(
    r"Accepted\s+\S+\s+for\s+(?:invalid user\s+)?\S+\s+from\s+(?P<addr>\S+)\s+port\s+\d+",
    re.IGNORECASE,
)
_FAILED = re.compile(
    r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?\S+\s+from\s+(?P<addr>\S+)\s+port\s+\d+",
    re.IGNORECASE,
)
_INVALID = re.compile(r"Invalid user\s+\S+\s+from\s+(?P<addr>\S+)", re.IGNORECASE)
_PAM = re.compile(r"authentication failure;.*rhost=(?P<addr>\S+)", re.IGNORECASE)
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)")
_SYSLOG = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


@dataclass
class SSHEvent:
    kind: str
    address: str
    when: str = ""


def parse_ssh_log(text: str) -> list[SSHEvent]:
    events: list[SSHEvent] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line == "-- No entries --":
            continue
        kind = None
        addr = None
        for pattern, name in (
            (_ACCEPTED, "accepted"),
            (_FAILED, "failed"),
            (_INVALID, "failed"),
            (_PAM, "failed"),
        ):
            match = pattern.search(line)
            if match:
                kind = name
                addr = match.group("addr").rstrip(":")
                break
        if not kind or not addr:
            continue
        when = ""
        iso = _ISO.match(line)
        syslog = _SYSLOG.match(line)
        if iso:
            when = iso.group(1)
        elif syslog:
            when = syslog.group(1)
        events.append(SSHEvent(kind=kind, address=addr, when=when))
    return events


def dedupe_events(events: list[SSHEvent]) -> list[SSHEvent]:
    seen: set[tuple[str, str, str]] = set()
    out: list[SSHEvent] = []
    for event in events:
        key = (event.when, event.kind, event.address)
        if key in seen:
            continue
        seen.add(key)
        out.append(event)
    return out


def read_auth_file(path: str, max_bytes: int = 262144) -> str:
    target = Path(path)
    size = target.stat().st_size
    with target.open("rb") as handle:
        if size > max_bytes:
            handle.seek(size - max_bytes)
            data = handle.read()
            newline = data.find(b"\n")
            if newline != -1:
                data = data[newline + 1 :]
        else:
            data = handle.read()
    return data.decode("utf-8", "replace")


def ssh_plate(events: list[SSHEvent], last_n: int, fail_broken: int, source: str) -> Plate:
    window = events[-last_n:] if last_n > 0 else events
    accepted = sum(1 for event in window if event.kind == "accepted")
    failed = sum(1 for event in window if event.kind == "failed")
    if failed >= fail_broken:
        status = "broken"
    elif failed > 0:
        status = "scored"
    else:
        status = "intact"
    if window:
        addr = window[-1].address
        detail = addr if len(addr) <= 14 else "see log"
    else:
        detail = "no events"
    evidence = [
        f"accepted: {accepted}",
        f"failed: {failed}",
        f"source: {source}",
    ]
    for event in window:
        stamp = f"{event.when} " if event.when else ""
        evidence.append(f"{stamp}{event.kind} {event.address}".strip())
    return Plate(
        name="ssh",
        status=status,
        headline=f"{failed} failed",
        detail=detail,
        evidence=evidence,
    )


def collect_ssh(runner, last_n: int = 20, fail_broken: int = 10, log_reader=None) -> Plate:
    events: list[SSHEvent] = []
    errors: list[str] = []
    readable = False
    journal_missing = False

    for unit in JOURNAL_UNITS:
        result = runner.run(journal_argv(unit))
        if result.not_found:
            journal_missing = True
            errors.append("journalctl not found")
            break
        if result.timed_out:
            errors.append(f"journalctl {unit} timed out")
            continue
        if access_denied(result):
            errors.append(f"journalctl {unit}: permission denied")
            continue
        text = result.stdout or ""
        if result.returncode not in (0, None) and not text.strip():
            hint = (result.stderr or "").lower()
            if "no journal" in hint:
                errors.append("no journal files")
            continue
        parsed = parse_ssh_log(text)
        if result.returncode == 0 or parsed:
            readable = True
        events.extend(parsed)

    events = dedupe_events(events)
    if events or (readable and not errors):
        return ssh_plate(events, last_n, fail_broken, "journal")

    reader = log_reader or read_auth_file
    file_error = None
    for path in AUTH_LOG_PATHS:
        try:
            text = reader(path)
        except FileNotFoundError:
            continue
        except PermissionError:
            file_error = f"permission denied: {path}"
            continue
        except OSError as exc:
            file_error = str(exc)
            continue
        return ssh_plate(parse_ssh_log(text), last_n, fail_broken, path)

    if file_error:
        return unknown_plate("ssh", file_error, "logs unreadable")
    if journal_missing and not file_error:
        return unknown_plate("ssh", "no ssh log source", "no log")
    if errors:
        return unknown_plate("ssh", errors[0], "logs unreadable")
    return unknown_plate("ssh", "no ssh log source", "no log")
