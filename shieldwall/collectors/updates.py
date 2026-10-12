from shieldwall.commands import APT_ARGV, CHECKUPDATES_ARGV, DNF_ARGV
from shieldwall.model import Plate, unknown_plate
from shieldwall.runner import access_denied


def parse_apt_upgradable(text: str) -> list[str]:
    names: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("Listing") or line.startswith("WARNING"):
            continue
        if line.startswith("E:") or line.startswith("W:"):
            continue
        token = line.split()[0]
        if "/" not in token and "[upgradable" not in line:
            continue
        names.append(token.split("/")[0])
    return names


def parse_dnf_check_update(text: str, returncode: int | None) -> list[str] | None:
    if returncode == 0:
        return []
    if returncode != 100:
        return None
    names: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("last metadata"):
            continue
        if line.endswith(":") or line.startswith("Obsoleting"):
            continue
        parts = line.split()
        if len(parts) >= 3 and "." in parts[0]:
            names.append(parts[0])
    return names


def parse_checkupdates(text: str, returncode: int | None) -> list[str] | None:
    if returncode == 2:
        return []
    if returncode not in (0, None):
        return None
    if returncode is None:
        return None
    names: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("::"):
            continue
        names.append(line.split()[0])
    return names


def updates_plate(backend: str, names: list[str]) -> Plate:
    count = len(names)
    evidence = [f"{count} pending via {backend}"]
    evidence.extend(names[:8])
    if count > 8:
        evidence.append(f"{count - 8} more")
    return Plate(
        name="updates",
        status="intact" if count == 0 else "scored",
        headline=f"{count} pending",
        detail=backend,
        evidence=evidence,
    )


def collect_updates(runner) -> Plate:
    apt = runner.run(APT_ARGV)
    if not apt.not_found:
        if apt.timed_out:
            return unknown_plate("updates", "apt timed out", "apt")
        if access_denied(apt):
            return unknown_plate("updates", "apt: permission denied", "apt")
        if apt.returncode != 0:
            return unknown_plate("updates", f"apt exited {apt.returncode}", "apt")
        return updates_plate("apt", parse_apt_upgradable(apt.stdout))

    dnf = runner.run(DNF_ARGV)
    if not dnf.not_found:
        if dnf.timed_out:
            return unknown_plate("updates", "dnf timed out", "dnf")
        if access_denied(dnf):
            return unknown_plate("updates", "dnf: permission denied", "dnf")
        names = parse_dnf_check_update(dnf.stdout, dnf.returncode)
        if names is None:
            return unknown_plate("updates", f"dnf exited {dnf.returncode}", "dnf")
        return updates_plate("dnf", names)

    pac = runner.run(CHECKUPDATES_ARGV)
    if not pac.not_found:
        if pac.timed_out:
            return unknown_plate("updates", "checkupdates timed out", "pacman")
        if access_denied(pac):
            return unknown_plate("updates", "checkupdates: permission denied", "pacman")
        names = parse_checkupdates(pac.stdout, pac.returncode)
        if names is None:
            return unknown_plate("updates", f"checkupdates exited {pac.returncode}", "pacman")
        return updates_plate("pacman", names)

    return unknown_plate("updates", "no package manager check command found", "no tool")
