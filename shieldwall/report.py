import socket

from shieldwall.collectors.firewall import collect_firewall
from shieldwall.collectors.ports import collect_ports
from shieldwall.collectors.secrets import collect_secrets
from shieldwall.collectors.ssh import collect_ssh
from shieldwall.collectors.updates import collect_updates
from shieldwall.config import allowlist_from_config, secrets_path, ssh_settings
from shieldwall.meter import armor_meter
from shieldwall.model import Report


def collect_report(
    config: dict | None = None,
    runner=None,
    proc_reader=None,
    log_reader=None,
    which=None,
    host: str | None = None,
) -> Report:
    config = config or {}
    if runner is None:
        from shieldwall.runner import Runner

        runner = Runner()
    last_n, fail_broken = ssh_settings(config)
    plates = [
        collect_firewall(runner),
        collect_ports(runner, allowlist_from_config(config), proc_reader=proc_reader),
        collect_ssh(runner, last_n=last_n, fail_broken=fail_broken, log_reader=log_reader),
        collect_updates(runner),
        collect_secrets(runner, secrets_path(config), which=which),
    ]
    meter = armor_meter([plate.status for plate in plates])
    name = host or socket.gethostname() or "local"
    return Report(host=name, plates=plates, meter=meter)
