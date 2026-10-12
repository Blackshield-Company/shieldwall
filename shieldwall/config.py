import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def default_config_path() -> Path:
    return Path.home() / ".config" / "shieldwall" / "config.toml"


def load_config(path: str | None = None) -> dict:
    if path is None:
        candidate = default_config_path()
        if not candidate.is_file():
            return {}
        target = candidate
    else:
        target = Path(path)
        if not target.is_file():
            raise FileNotFoundError(f"config not found: {path}")
    with target.open("rb") as handle:
        data = tomllib.load(handle)
    if not isinstance(data, dict):
        raise ValueError("config must be a TOML table")
    return data


@dataclass
class Allowlist:
    any_proto: set[int] = field(default_factory=set)
    by_proto: dict[str, set[int]] = field(default_factory=dict)
    configured: bool = False

    def allows(self, proto: str, port: int) -> bool:
        if port in self.any_proto:
            return True
        return port in self.by_proto.get(proto, set())


def _add_port(allowlist: Allowlist, port: int, proto: str | None) -> None:
    if proto:
        allowlist.by_proto.setdefault(proto.lower(), set()).add(port)
    else:
        allowlist.any_proto.add(port)


def _parse_allow_item(allowlist: Allowlist, item: object) -> None:
    if isinstance(item, int):
        _add_port(allowlist, item, None)
        return
    if isinstance(item, str):
        text = item.strip()
        if "/" in text:
            port_s, proto = text.split("/", 1)
            _add_port(allowlist, int(port_s), proto.strip().lower())
        else:
            _add_port(allowlist, int(text), None)
        return
    if isinstance(item, dict):
        port = int(item["port"])
        proto = item.get("proto")
        _add_port(allowlist, port, str(proto).lower() if proto else None)
        return
    raise ValueError(f"unsupported allowlist entry: {item!r}")


def allowlist_from_config(cfg: dict) -> Allowlist:
    ports = cfg.get("ports") or {}
    allowlist = Allowlist()
    items = ports.get("allow") or []
    proto_map = ports.get("proto") or {}
    if items or proto_map:
        allowlist.configured = True
    for item in items:
        _parse_allow_item(allowlist, item)
    for proto, values in proto_map.items():
        for value in values:
            _add_port(allowlist, int(value), str(proto))
    return allowlist


def ssh_settings(cfg: dict) -> tuple[int, int]:
    section = cfg.get("ssh") or {}
    last_n = int(section.get("last_n", 20))
    fail_broken = int(section.get("fail_broken", 10))
    if last_n < 1:
        last_n = 1
    if fail_broken < 1:
        fail_broken = 1
    return last_n, fail_broken


def secrets_path(cfg: dict) -> str:
    section = cfg.get("secrets") or {}
    path = section.get("path") or "."
    return str(path)


def serve_settings(cfg: dict) -> tuple[str, int]:
    section = cfg.get("serve") or {}
    host = str(section.get("host", "127.0.0.1"))
    port = int(section.get("port", 8787))
    return host, port
