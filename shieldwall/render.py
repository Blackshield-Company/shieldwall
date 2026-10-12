import os
import sys

from shieldwall.meter import meter_phrase
from shieldwall.model import DISCLAIMER, Report
from shieldwall.palette import RGB, STATUS_COLOR

WIDTH = 78
COL_W = 15


def paint(text: str, name: str, enabled: bool) -> str:
    if not enabled:
        return text
    red, green, blue = RGB[name]
    return f"\033[38;2;{red};{green};{blue}m{text}\033[0m"


def color_enabled(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _cell(text: str) -> str:
    text = " ".join(str(text).split())
    if len(text) > COL_W - 1:
        text = text[: COL_W - 1]
    return text.ljust(COL_W)


def _row(parts: list[str]) -> str:
    return "|" + "".join(parts).ljust(WIDTH - 2) + "|"


def _rule() -> str:
    return "+" + "-" * (WIDTH - 2) + "+"


def render_text(report: Report, color: bool = True) -> str:
    statuses = [plate.status for plate in report.plates]
    phrase = meter_phrase(report.meter, statuses)
    filled = round(report.meter.score / 100 * 20)
    bar = "#" * filled + ":" * (20 - filled)
    bar_color = report.meter.label if report.meter.label in RGB else "bone"
    host = report.host if len(report.host) <= 24 else report.host[:24]
    left = " SHIELDWALL"
    right = f"host: {host} "
    gap = WIDTH - 2 - len(left) - len(right)
    if gap < 1:
        gap = 1
        right = right[: max(0, WIDTH - 2 - len(left) - 1)]
    header = "|" + paint(left, "blood", color) + (" " * gap) + paint(right, "bone", color) + "|"
    meter_plain = f"  [{bar}]  ARMOR {report.meter.score:<3}  {phrase}"
    meter_line = "|" + paint(meter_plain.ljust(WIDTH - 2), bar_color, color) + "|"
    note = f"  {DISCLAIMER}"
    note_line = "|" + paint(note.ljust(WIDTH - 2), "bone", color) + "|"
    names = _row([_cell(plate.name.upper()) for plate in report.plates])
    headlines = _row([_cell(plate.headline) for plate in report.plates])
    details = _row([_cell(plate.detail) for plate in report.plates])
    status_cells = []
    for plate in report.plates:
        token = _cell(f"[{plate.status}]")
        status_cells.append(paint(token, STATUS_COLOR.get(plate.status, "bone"), color))
    pad = " " * max(0, WIDTH - 2 - COL_W * len(report.plates))
    statuses_row = "|" + "".join(status_cells) + pad + "|"
    lines = [
        _rule(),
        header,
        "|" + " " * (WIDTH - 2) + "|",
        meter_line,
        note_line,
        "|" + " " * (WIDTH - 2) + "|",
        names,
        headlines,
        details,
        statuses_row,
        _rule(),
    ]
    for item in _footer(report):
        text = " " + item
        if len(text) > WIDTH - 2:
            text = text[: WIDTH - 3] + "."
        lines.append("|" + text.ljust(WIDTH - 2) + "|")
    lines.append(_rule())
    return "\n".join(lines)


def _footer(report: Report) -> list[str]:
    lines: list[str] = []
    for plate in report.plates:
        if plate.status != "broken":
            continue
        for evidence in plate.evidence[:2]:
            lines.append(evidence)
            if len(lines) >= 3:
                break
        if len(lines) >= 3:
            break
    if not lines:
        for plate in report.plates:
            if plate.status == "unknown" and plate.error:
                lines.append(f"{plate.name}: {plate.error}")
            if len(lines) >= 2:
                break
    lines.append("no changes will be applied from this screen")
    return lines[:4]
