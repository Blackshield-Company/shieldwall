NFT_ARGV = ["nft", "list", "ruleset"]
FIREWALLD_STATE_ARGV = ["firewall-cmd", "--state"]
FIREWALLD_LIST_ARGV = ["firewall-cmd", "--list-all"]
UFW_STATUS_ARGV = ["ufw", "status"]
UFW_VERBOSE_ARGV = ["ufw", "status", "verbose"]
SS_ARGV = ["ss", "-H", "-tulpn"]
APT_ARGV = ["apt", "list", "--upgradable"]
DNF_ARGV = ["dnf", "check-update"]
CHECKUPDATES_ARGV = ["checkupdates"]
JOURNAL_UNITS = ("ssh", "sshd")
JOURNAL_LIMIT = "400"
AUTH_LOG_PATHS = ("/var/log/auth.log", "/var/log/secure")


def journal_argv(unit: str) -> list[str]:
    if unit not in JOURNAL_UNITS:
        raise ValueError("unsupported journal unit")
    return ["journalctl", "-u", unit, "-o", "short-iso", "-n", JOURNAL_LIMIT, "--no-pager"]


def secretsweep_argv(path: str) -> list[str]:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("invalid scan path")
    return ["secretsweep", "scan", path, "--format", "json"]
