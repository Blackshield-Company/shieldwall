import tempfile
import unittest
from pathlib import Path

from shieldwall.config import allowlist_from_config, load_config, ssh_settings


class ConfigTests(unittest.TestCase):
    def test_tomllib_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(
                "\n".join(
                    [
                        "[ports]",
                        "allow = [22, \"80/tcp\"]",
                        "",
                        "[ports.proto]",
                        "udp = [53]",
                        "",
                        "[ssh]",
                        "last_n = 5",
                        "fail_broken = 3",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            cfg = load_config(str(path))
            allow = allowlist_from_config(cfg)
            self.assertTrue(allow.configured)
            self.assertTrue(allow.allows("tcp", 22))
            self.assertTrue(allow.allows("udp", 22))
            self.assertTrue(allow.allows("tcp", 80))
            self.assertFalse(allow.allows("udp", 80))
            self.assertTrue(allow.allows("udp", 53))
            self.assertEqual(ssh_settings(cfg), (5, 3))

    def test_missing_explicit_config(self):
        with self.assertRaises(FileNotFoundError):
            load_config("/tmp/shieldwall-no-such-config.toml")

    def test_empty_config_allowlist(self):
        allow = allowlist_from_config({})
        self.assertFalse(allow.configured)
        self.assertFalse(allow.allows("tcp", 22))
