import unittest

from shieldwall.collectors.ports import (
    collect_ports,
    decode_proc_ip,
    parse_proc_net,
    parse_ss,
    plate_from_listeners,
)
from shieldwall.commands import SS_ARGV
from shieldwall.config import Allowlist, allowlist_from_config
from tests.fakes import FakeRunner, canned

SS_TEXT = """
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=1,fd=4))
tcp   LISTEN 0      511                *:443             *:*    users:(("caddy",pid=9,fd=8))
udp   UNCONN 0      0      0.0.0.0%virbr0:53         0.0.0.0:*    users:(("dnsmasq",pid=2,fd=5))
"""

PROC_TCP = """
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
"""

PROC_TCP6 = """
  sl  local_address                         rem_address                         st tx_queue rx_queue
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000
"""

PROC_UDP = """
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9 2 0000000000000000
   1: 00000000:0045 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 9 2 0000000000000000
"""


class PortParseTests(unittest.TestCase):
    def test_ss_listeners_and_process(self):
        found = parse_ss(SS_TEXT)
        ports = {(item.proto, item.port, item.process) for item in found}
        self.assertIn(("tcp", 22, "sshd"), ports)
        self.assertIn(("tcp", 443, "caddy"), ports)
        self.assertIn(("udp", 53, "dnsmasq"), ports)

    def test_proc_decodes_listen_states(self):
        self.assertEqual(decode_proc_ip("0100007F"), "127.0.0.1")
        self.assertEqual(decode_proc_ip("00000000"), "0.0.0.0")
        self.assertEqual(decode_proc_ip("00000000000000000000000001000000"), "::1")
        tcp = parse_proc_net(PROC_TCP, "tcp")
        self.assertEqual({(item.port, item.bind) for item in tcp}, {(22, "0.0.0.0"), (631, "127.0.0.1")})
        tcp6 = parse_proc_net(PROC_TCP6, "tcp6")
        self.assertEqual(tcp6[0].port, 443)
        self.assertEqual(tcp6[0].bind, "::")
        udp = parse_proc_net(PROC_UDP, "udp")
        self.assertEqual([item.port for item in udp], [53])


class PortAllowlistTests(unittest.TestCase):
    def test_unexpected_port_is_broken(self):
        allow = allowlist_from_config({"ports": {"allow": [22]}})
        plate = plate_from_listeners(parse_ss(SS_TEXT), allow, "ss")
        self.assertEqual(plate.status, "broken")
        blob = "\n".join(plate.evidence)
        self.assertIn(":443", blob)
        self.assertIn("not in allowlist", blob)
        self.assertIn(":22", blob)
        self.assertIn("allow", blob)

    def test_allowed_ports_are_intact(self):
        allow = allowlist_from_config(
            {"ports": {"allow": [22, 443], "proto": {"udp": [53]}}}
        )
        plate = plate_from_listeners(parse_ss(SS_TEXT), allow, "ss")
        self.assertEqual(plate.status, "intact")

    def test_proto_specific_allowlist(self):
        allow = allowlist_from_config({"ports": {"allow": ["22/tcp"], "proto": {"udp": [53]}}})
        self.assertTrue(allow.allows("tcp", 22))
        self.assertFalse(allow.allows("udp", 22))
        self.assertTrue(allow.allows("udp", 53))
        self.assertFalse(allow.allows("tcp", 53))

    def test_empty_allowlist_flags_listeners(self):
        plate = plate_from_listeners(parse_ss(SS_TEXT), Allowlist(), "ss")
        self.assertEqual(plate.status, "broken")
        self.assertIn("no allowlist configured", plate.evidence[0])

    def test_no_listeners_intact(self):
        allow = allowlist_from_config({"ports": {"allow": [22]}})
        plate = plate_from_listeners([], allow, "ss")
        self.assertEqual(plate.status, "intact")

    def test_ss_command_uses_allowlist(self):
        allow = allowlist_from_config({"ports": {"allow": [22]}})
        runner = FakeRunner({tuple(SS_ARGV): canned(SS_ARGV, SS_TEXT)})
        plate = collect_ports(runner, allow, proc_reader=lambda: {})
        self.assertEqual(plate.status, "broken")
        self.assertEqual(runner.calls, [tuple(SS_ARGV)])

    def test_proc_fallback_when_ss_missing(self):
        allow = allowlist_from_config({"ports": {"allow": [22, 443], "proto": {"udp": [53]}}})
        runner = FakeRunner({})
        plate = collect_ports(
            runner,
            allow,
            proc_reader=lambda: {"tcp": PROC_TCP, "tcp6": PROC_TCP6, "udp": PROC_UDP, "udp6": ""},
        )
        self.assertEqual(plate.status, "broken")
        self.assertIn("source: proc", plate.evidence)
        blob = "\n".join(plate.evidence)
        self.assertIn(":631", blob)
        self.assertIn("not in allowlist", blob)

    def test_missing_ss_and_proc_is_unknown(self):
        plate = collect_ports(FakeRunner({}), Allowlist(configured=True), proc_reader=lambda: {})
        self.assertEqual(plate.status, "unknown")
        self.assertNotEqual(plate.status, "intact")
        self.assertIsNotNone(plate.error)

    def test_ss_permission_falls_back_then_unknown(self):
        runner = FakeRunner(
            {tuple(SS_ARGV): canned(SS_ARGV, stderr="permission denied", returncode=1)}
        )
        plate = collect_ports(runner, Allowlist(), proc_reader=lambda: {})
        self.assertEqual(plate.status, "unknown")
