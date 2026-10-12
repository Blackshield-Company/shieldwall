import re

from shieldwall.commands import (
    FIREWALLD_LIST_ARGV,
    FIREWALLD_STATE_ARGV,
    NFT_ARGV,
    UFW_STATUS_ARGV,
    UFW_VERBOSE_ARGV,
)
from shieldwall.model import Plate, unknown_plate
from shieldwall.runner import access_denied

_NFT_INPUT = re.compile(
    r"hook\s+input\b[^}]*?policy\s+(accept|drop|reject)",
    re.IGNORECASE,
)
_UFW_STATUS = re.compile(r"Status:\s*(active|inactive)", re.IGNORECASE)
_UFW_DEFAULT = re.compile(r"Default:\s*([A-Za-z]+)\s*\(incoming\)", re.IGNORECASE)
_FWD_TARGET = re.compile(r"^\s*target:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)


def parse_nft_ruleset(text: str) -> dict | None:
    policies = [item.lower() for item in _NFT_INPUT.findall(text)]
    if not policies:
        return None
    if all(item in ("drop", "reject") for item in policies):
        status = "intact"
        policy = policies[0]
    else:
        status = "scored"
        policy = "accept" if "accept" in policies else policies[0]
    return {"backend": "nft", "status": status, "policy": policy, "policies": policies}


def parse_firewalld_state(text: str) -> str | None:
    low = text.lower()
    if "not running" in low:
        return "stopped"
    if re.search(r"\brunning\b", low):
        return "running"
    return None


def parse_firewalld_target(text: str) -> str | None:
    match = _FWD_TARGET.search(text)
    if not match:
        return None
    return match.group(1)


def parse_ufw_status(text: str) -> bool | None:
    match = _UFW_STATUS.search(text)
    if not match:
        return None
    return match.group(1).lower() == "active"


def parse_ufw_default(text: str) -> str | None:
    match = _UFW_DEFAULT.search(text)
    if not match:
        return None
    return match.group(1).lower()


def _nft_plate(info: dict) -> Plate:
    policy = info["policy"]
    return Plate(
        name="firewall",
        status=info["status"],
        headline="nft enabled",
        detail=f"{policy} in",
        evidence=[
            f"nft input policy {policy}",
            "policies: " + ", ".join(info["policies"]),
        ],
    )


def _firewalld_plate(policy: str | None) -> Plate:
    if policy is None:
        return Plate(
            name="firewall",
            status="scored",
            headline="fwd running",
            detail="policy unknown",
            evidence=["firewalld running", "default policy not read"],
        )
    norm = policy.lower().strip("%")
    if norm in ("drop", "reject", "default"):
        shown = "drop" if norm == "drop" else "reject"
        return Plate(
            name="firewall",
            status="intact",
            headline="fwd running",
            detail=f"{shown} in",
            evidence=["firewalld running", f"target {shown}"],
        )
    if norm == "accept":
        return Plate(
            name="firewall",
            status="scored",
            headline="fwd running",
            detail="accept in",
            evidence=["firewalld running", "target accept"],
        )
    return Plate(
        name="firewall",
        status="scored",
        headline="fwd running",
        detail="policy unknown",
        evidence=["firewalld running", f"target {norm}"],
    )


def _ufw_plate(policy: str | None) -> Plate:
    if policy in ("deny", "reject", "drop"):
        return Plate(
            name="firewall",
            status="intact",
            headline="ufw active",
            detail=f"{policy} in",
            evidence=["ufw active", f"default incoming {policy}"],
        )
    if policy in ("allow", "accept"):
        return Plate(
            name="firewall",
            status="scored",
            headline="ufw active",
            detail="allow in",
            evidence=["ufw active", "default incoming allow"],
        )
    return Plate(
        name="firewall",
        status="scored",
        headline="ufw active",
        detail="policy unknown",
        evidence=["ufw active", "default policy not read"],
    )


def collect_firewall(runner) -> Plate:
    errors: list[str] = []
    saw_tool = False
    disabled: list[str] = []

    nft = runner.run(NFT_ARGV)
    if not nft.not_found:
        saw_tool = True
        if nft.timed_out:
            errors.append("nft timed out")
        elif access_denied(nft):
            errors.append("nft: permission denied")
        elif nft.returncode == 0:
            info = parse_nft_ruleset(nft.stdout)
            if info is not None:
                return _nft_plate(info)
            disabled.append("nft has no input policy")
        else:
            errors.append(f"nft exited {nft.returncode}")

    state = runner.run(FIREWALLD_STATE_ARGV)
    if not state.not_found:
        saw_tool = True
        blob = state.blob()
        if state.timed_out:
            errors.append("firewall-cmd timed out")
        elif access_denied(state):
            errors.append("firewall-cmd: permission denied")
        else:
            kind = parse_firewalld_state(blob)
            if kind == "running":
                listing = runner.run(FIREWALLD_LIST_ARGV)
                policy = None
                if (
                    not listing.not_found
                    and not listing.timed_out
                    and not access_denied(listing)
                    and listing.returncode == 0
                ):
                    policy = parse_firewalld_target(listing.stdout)
                return _firewalld_plate(policy)
            if kind == "stopped":
                disabled.append("firewalld not running")
            else:
                errors.append("firewall-cmd state unreadable")

    ufw = runner.run(UFW_STATUS_ARGV)
    if not ufw.not_found:
        saw_tool = True
        blob = ufw.blob()
        if ufw.timed_out:
            errors.append("ufw timed out")
        elif access_denied(ufw):
            errors.append("ufw: permission denied")
        else:
            active = parse_ufw_status(blob)
            if active is True:
                verbose = runner.run(UFW_VERBOSE_ARGV)
                policy = parse_ufw_default(blob)
                if (
                    not verbose.not_found
                    and not verbose.timed_out
                    and not access_denied(verbose)
                ):
                    policy = parse_ufw_default(verbose.blob()) or policy
                return _ufw_plate(policy)
            if active is False:
                disabled.append("ufw inactive")
            else:
                errors.append("ufw status unreadable")

    if errors:
        return unknown_plate("firewall", errors[0], "unreadable")
    if disabled:
        return Plate(
            name="firewall",
            status="broken",
            headline="disabled",
            detail="no policy",
            evidence=disabled,
        )
    if not saw_tool:
        return unknown_plate("firewall", "no firewall tool found", "no tool")
    return unknown_plate("firewall", "firewall state unknown", "no policy")
