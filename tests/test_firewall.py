import unittest

from shieldwall.collectors.firewall import (
    collect_firewall,
    parse_firewalld_state,
    parse_firewalld_target,
    parse_nft_ruleset,
    parse_ufw_default,
    parse_ufw_status,
)
from shieldwall.commands import (
    FIREWALLD_LIST_ARGV,
    FIREWALLD_STATE_ARGV,
    NFT_ARGV,
    UFW_STATUS_ARGV,
    UFW_VERBOSE_ARGV,
)
from tests.fakes import FakeRunner, canned

NFT_DROP = """
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
"""

NFT_ACCEPT = """
table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
	}
}
"""

NFT_MIXED = """
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
	}
	chain input_extra {
		type filter hook input priority filter; policy accept;
	}
}
"""

FIREWALLD_DROP = """
public (active)
  target: DROP
  interfaces: eth0
  services: ssh
"""

FIREWALLD_ACCEPT = """
public (active)
  target: ACCEPT
"""

FIREWALLD_DEFAULT = """
public (active)
  target: default
"""

UFW_VERBOSE_DENY = """
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
"""

UFW_VERBOSE_ALLOW = """
Status: active
Default: allow (incoming), allow (outgoing), deny (routed)
"""


class FirewallParseTests(unittest.TestCase):
    def test_nft_drop_ignores_forward_accept(self):
        info = parse_nft_ruleset(NFT_DROP)
        self.assertEqual(info["status"], "intact")
        self.assertEqual(info["policy"], "drop")

    def test_nft_accept_is_scored(self):
        info = parse_nft_ruleset(NFT_ACCEPT)
        self.assertEqual(info["status"], "scored")

    def test_nft_mixed_input_is_scored(self):
        info = parse_nft_ruleset(NFT_MIXED)
        self.assertEqual(info["status"], "scored")

    def test_nft_empty_is_not_a_policy(self):
        self.assertIsNone(parse_nft_ruleset(""))

    def test_firewalld_state_variants(self):
        self.assertEqual(parse_firewalld_state("running\n"), "running")
        self.assertEqual(parse_firewalld_state("not running\n"), "stopped")

    def test_firewalld_targets(self):
        self.assertEqual(parse_firewalld_target(FIREWALLD_DROP), "DROP")
        self.assertEqual(parse_firewalld_target(FIREWALLD_ACCEPT), "ACCEPT")
        self.assertEqual(parse_firewalld_target(FIREWALLD_DEFAULT), "default")

    def test_ufw_status_and_default(self):
        self.assertIs(parse_ufw_status("Status: inactive\n"), False)
        self.assertIs(parse_ufw_status(UFW_VERBOSE_DENY), True)
        self.assertEqual(parse_ufw_default(UFW_VERBOSE_DENY), "deny")
        self.assertEqual(parse_ufw_default(UFW_VERBOSE_ALLOW), "allow")


class FirewallCollectTests(unittest.TestCase):
    def test_nft_drop_intact(self):
        runner = FakeRunner({tuple(NFT_ARGV): canned(NFT_ARGV, NFT_DROP)})
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "intact")
        self.assertIn("drop", plate.detail)
        self.assertIsNone(plate.error)

    def test_nft_accept_scored(self):
        runner = FakeRunner({tuple(NFT_ARGV): canned(NFT_ARGV, NFT_ACCEPT)})
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "scored")

    def test_nft_permission_is_unknown_not_intact(self):
        runner = FakeRunner(
            {
                tuple(NFT_ARGV): canned(
                    NFT_ARGV,
                    stderr="Operation not permitted (you must be root)",
                    returncode=1,
                )
            }
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "unknown")
        self.assertNotEqual(plate.status, "intact")
        self.assertIsNotNone(plate.error)

    def test_firewalld_drop_intact(self):
        runner = FakeRunner(
            {
                tuple(FIREWALLD_STATE_ARGV): canned(FIREWALLD_STATE_ARGV, "running\n"),
                tuple(FIREWALLD_LIST_ARGV): canned(FIREWALLD_LIST_ARGV, FIREWALLD_DROP),
            }
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "intact")
        self.assertIn("firewalld running", plate.evidence)

    def test_firewalld_accept_scored(self):
        runner = FakeRunner(
            {
                tuple(FIREWALLD_STATE_ARGV): canned(FIREWALLD_STATE_ARGV, "running\n"),
                tuple(FIREWALLD_LIST_ARGV): canned(FIREWALLD_LIST_ARGV, FIREWALLD_ACCEPT),
            }
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "scored")

    def test_firewalld_default_target_intact(self):
        runner = FakeRunner(
            {
                tuple(FIREWALLD_STATE_ARGV): canned(FIREWALLD_STATE_ARGV, "running\n"),
                tuple(FIREWALLD_LIST_ARGV): canned(FIREWALLD_LIST_ARGV, FIREWALLD_DEFAULT),
            }
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "intact")

    def test_firewalld_stopped_is_broken(self):
        runner = FakeRunner(
            {
                tuple(FIREWALLD_STATE_ARGV): canned(
                    FIREWALLD_STATE_ARGV, "not running\n", returncode=252
                )
            }
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "broken")
        self.assertIn("firewalld not running", plate.evidence)

    def test_ufw_deny_intact(self):
        runner = FakeRunner(
            {
                tuple(UFW_STATUS_ARGV): canned(UFW_STATUS_ARGV, "Status: active\n"),
                tuple(UFW_VERBOSE_ARGV): canned(UFW_VERBOSE_ARGV, UFW_VERBOSE_DENY),
            }
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "intact")
        self.assertIn("deny", plate.detail)

    def test_ufw_allow_scored(self):
        runner = FakeRunner(
            {
                tuple(UFW_STATUS_ARGV): canned(UFW_STATUS_ARGV, "Status: active\n"),
                tuple(UFW_VERBOSE_ARGV): canned(UFW_VERBOSE_ARGV, UFW_VERBOSE_ALLOW),
            }
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "scored")

    def test_ufw_inactive_is_broken(self):
        runner = FakeRunner(
            {tuple(UFW_STATUS_ARGV): canned(UFW_STATUS_ARGV, "Status: inactive\n")}
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "broken")
        self.assertIn("ufw inactive", plate.evidence)

    def test_ufw_needs_root_is_unknown(self):
        runner = FakeRunner(
            {
                tuple(UFW_STATUS_ARGV): canned(
                    UFW_STATUS_ARGV,
                    stderr="ERROR: You need to be root to run this script",
                    returncode=1,
                )
            }
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "unknown")

    def test_no_tool_is_unknown(self):
        plate = collect_firewall(FakeRunner({}))
        self.assertEqual(plate.status, "unknown")
        self.assertIn("no firewall tool", plate.error)

    def test_permission_plus_inactive_stays_unknown(self):
        runner = FakeRunner(
            {
                tuple(NFT_ARGV): canned(
                    NFT_ARGV, stderr="permission denied", returncode=1
                ),
                tuple(UFW_STATUS_ARGV): canned(UFW_STATUS_ARGV, "Status: inactive\n"),
            }
        )
        plate = collect_firewall(runner)
        self.assertEqual(plate.status, "unknown")
