import unittest

from shieldwall.collectors.ssh import collect_ssh, parse_ssh_log, ssh_plate
from shieldwall.commands import journal_argv
from tests.fakes import FakeRunner, canned, missing_log

JOURNAL = """
2026-10-12T10:15:01+0000 host sshd[123]: Accepted publickey for notausername from 192.0.2.10 port 54321 ssh2
2026-10-12T10:16:02+0000 host sshd[124]: Failed password for invalid user admin from 198.51.100.20 port 22 ssh2
2026-10-12T10:17:03+0000 host sshd[125]: Invalid user guest from 203.0.113.5
2026-10-12T10:18:04+0000 host sshd[126]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.8
"""

AUTH = """
Oct 12 10:15:01 host sshd[123]: Accepted password for notausername from 192.0.2.10 port 22 ssh2
Oct 12 10:16:02 host sshd[124]: Failed password for user from 198.51.100.20 port 22 ssh2
"""


class SSHParseTests(unittest.TestCase):
    def test_journal_accepted_and_failed(self):
        events = parse_ssh_log(JOURNAL)
        self.assertEqual(len(events), 4)
        self.assertEqual(events[0].kind, "accepted")
        self.assertEqual(events[0].address, "192.0.2.10")
        self.assertEqual(events[1].kind, "failed")
        self.assertEqual(events[1].address, "198.51.100.20")
        self.assertEqual(events[2].address, "203.0.113.5")
        self.assertEqual(events[3].address, "192.0.2.8")
        blob = " ".join(f"{event.kind} {event.address}" for event in events)
        self.assertNotIn("notausername", blob)
        self.assertNotIn("admin", blob)

    def test_auth_log_variant(self):
        events = parse_ssh_log(AUTH)
        self.assertEqual(events[0].when, "Oct 12 10:15:01")
        self.assertEqual(events[1].kind, "failed")
        self.assertEqual(events[1].address, "198.51.100.20")

    def test_last_n_and_thresholds(self):
        events = parse_ssh_log("\n".join(
            f"2026-10-12T10:00:{index:02d}+0000 host sshd[1]: Failed password for user from 192.0.2.10 port 22 ssh2"
            for index in range(12)
        ))
        window = ssh_plate(events, last_n=5, fail_broken=10, source="journal")
        self.assertEqual(window.status, "scored")
        self.assertEqual(window.headline, "5 failed")
        broken = ssh_plate(events, last_n=20, fail_broken=10, source="journal")
        self.assertEqual(broken.status, "broken")
        quiet = ssh_plate(parse_ssh_log(AUTH[:0]), last_n=20, fail_broken=10, source="journal")
        self.assertEqual(quiet.status, "intact")


class SSHCollectTests(unittest.TestCase):
    def _journal_map(self, text, stderr="", returncode=0):
        mapping = {}
        for unit in ("ssh", "sshd"):
            argv = journal_argv(unit)
            mapping[tuple(argv)] = canned(argv, text if unit == "sshd" else "", stderr, returncode)
        return mapping

    def test_journal_scored_and_hides_username(self):
        runner = FakeRunner(self._journal_map(JOURNAL))
        plate = collect_ssh(runner, log_reader=missing_log)
        self.assertEqual(plate.status, "scored")
        blob = "\n".join(plate.evidence)
        self.assertIn("192.0.2.10", blob)
        self.assertIn("198.51.100.20", blob)
        self.assertNotIn("notausername", blob)
        self.assertNotIn("Accepted publickey for", blob)

    def test_auth_log_fallback(self):
        runner = FakeRunner({})

        def reader(path):
            if path == "/var/log/auth.log":
                return AUTH
            raise FileNotFoundError(path)

        plate = collect_ssh(runner, log_reader=reader)
        self.assertEqual(plate.status, "scored")
        self.assertIn("source: /var/log/auth.log", plate.evidence)
        self.assertNotIn("notausername", "\n".join(plate.evidence))

    def test_permission_is_unknown_not_intact(self):
        mapping = {}
        for unit in ("ssh", "sshd"):
            argv = journal_argv(unit)
            mapping[tuple(argv)] = canned(
                argv,
                stderr="Hint: You are currently not seeing messages from other users and the system.",
                returncode=0,
            )
        plate = collect_ssh(FakeRunner(mapping), log_reader=missing_log)
        self.assertEqual(plate.status, "unknown")
        self.assertNotEqual(plate.status, "intact")

    def test_no_source_is_unknown(self):
        plate = collect_ssh(FakeRunner({}), log_reader=missing_log)
        self.assertEqual(plate.status, "unknown")
        self.assertIn("no ssh log", plate.error)

    def test_journal_unit_is_fixed(self):
        self.assertEqual(journal_argv("ssh")[0:4], ["journalctl", "-u", "ssh", "-o"])
        self.assertIn("short-iso", journal_argv("sshd"))
        with self.assertRaises(ValueError):
            journal_argv("ssh;id")
