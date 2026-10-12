import unittest

from shieldwall.collectors.updates import (
    collect_updates,
    parse_apt_upgradable,
    parse_checkupdates,
    parse_dnf_check_update,
)
from shieldwall.commands import APT_ARGV, CHECKUPDATES_ARGV, DNF_ARGV
from tests.fakes import FakeRunner, canned

APT_PENDING = """
WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Listing...
bash/stable 5.2-1 amd64 [upgradable from: 5.1-1]
openssl/stable 3.0.13-1 amd64 [upgradable from: 3.0.12-1]
"""

DNF_PENDING = """
Last metadata expiration check: 1 day ago
bash.x86_64      5.2.26-1   updates
openssl.x86_64   3.0.13-1   updates
"""

PAC_PENDING = """
bash 5.2.26-1 -> 5.2.26-2
"""


class UpdateParseTests(unittest.TestCase):
    def test_apt_pending_and_empty(self):
        self.assertEqual(parse_apt_upgradable(APT_PENDING), ["bash", "openssl"])
        self.assertEqual(parse_apt_upgradable("Listing...\n"), [])

    def test_dnf_exit_codes(self):
        self.assertEqual(parse_dnf_check_update(DNF_PENDING, 100), ["bash.x86_64", "openssl.x86_64"])
        self.assertEqual(parse_dnf_check_update("Last metadata expiration check: now\n", 0), [])
        self.assertIsNone(parse_dnf_check_update("Error: lock\n", 1))

    def test_checkupdates_variants(self):
        self.assertEqual(parse_checkupdates(PAC_PENDING, 0), ["bash"])
        self.assertEqual(parse_checkupdates("", 2), [])
        self.assertIsNone(parse_checkupdates("error\n", 1))


class UpdateCollectTests(unittest.TestCase):
    def test_apt_scored(self):
        runner = FakeRunner({tuple(APT_ARGV): canned(APT_ARGV, APT_PENDING)})
        plate = collect_updates(runner)
        self.assertEqual(plate.status, "scored")
        self.assertEqual(plate.detail, "apt")
        self.assertEqual(plate.headline, "2 pending")
        self.assertEqual(runner.calls, [tuple(APT_ARGV)])

    def test_apt_none_intact(self):
        runner = FakeRunner({tuple(APT_ARGV): canned(APT_ARGV, "Listing...\n")})
        plate = collect_updates(runner)
        self.assertEqual(plate.status, "intact")

    def test_dnf_variant(self):
        runner = FakeRunner({tuple(DNF_ARGV): canned(DNF_ARGV, DNF_PENDING, returncode=100)})
        plate = collect_updates(runner)
        self.assertEqual(plate.status, "scored")
        self.assertEqual(plate.detail, "dnf")

    def test_pacman_variant(self):
        runner = FakeRunner({tuple(CHECKUPDATES_ARGV): canned(CHECKUPDATES_ARGV, PAC_PENDING)})
        plate = collect_updates(runner)
        self.assertEqual(plate.status, "scored")
        self.assertEqual(plate.detail, "pacman")

    def test_pacman_none_intact(self):
        runner = FakeRunner({tuple(CHECKUPDATES_ARGV): canned(CHECKUPDATES_ARGV, "", returncode=2)})
        plate = collect_updates(runner)
        self.assertEqual(plate.status, "intact")

    def test_missing_tool_unknown(self):
        runner = FakeRunner({})
        plate = collect_updates(runner)
        self.assertEqual(plate.status, "unknown")
        self.assertEqual(
            runner.calls,
            [tuple(APT_ARGV), tuple(DNF_ARGV), tuple(CHECKUPDATES_ARGV)],
        )
        for call in runner.calls:
            self.assertNotIn("install", call)
            self.assertNotIn("upgrade", call)

    def test_apt_permission_unknown(self):
        runner = FakeRunner(
            {
                tuple(APT_ARGV): canned(
                    APT_ARGV,
                    stderr="E: Could not open lock file - open (13: Permission denied)",
                    returncode=100,
                )
            }
        )
        plate = collect_updates(runner)
        self.assertEqual(plate.status, "unknown")
        self.assertNotEqual(plate.status, "intact")

    def test_apt_lock_unknown(self):
        runner = FakeRunner(
            {tuple(APT_ARGV): canned(APT_ARGV, stderr="E: Could not get lock", returncode=100)}
        )
        plate = collect_updates(runner)
        self.assertEqual(plate.status, "unknown")
