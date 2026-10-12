import json
import tempfile
import unittest
from pathlib import Path

from shieldwall.collectors.secrets import collect_secrets, parse_secretsweep
from shieldwall.commands import secretsweep_argv
from shieldwall.model import DISCLAIMER
from shieldwall.render import render_text
from shieldwall.report import collect_report
from tests.fakes import FakeRunner, canned

EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB = "ghp_" + ("a" * 36)
PASSWORD = "example-secret-value"
PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----"


class SecretTests(unittest.TestCase):
    def test_builtin_redacts_and_honors_ignore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".shieldwallignore").write_text("# comment\n\nsecret.txt\nskipme/\n", encoding="utf-8")
            (root / "ok.py").write_text(f"token = '{EXAMPLE_KEY}'\n", encoding="utf-8")
            (root / "secret.txt").write_text(EXAMPLE_KEY + "\n", encoding="utf-8")
            skipped = root / "skipme"
            skipped.mkdir()
            (skipped / "key.txt").write_text(PRIVATE + "\nnot-a-real-key\n", encoding="utf-8")
            git = root / ".git"
            git.mkdir()
            (git / "hidden.txt").write_text(GITHUB + "\n", encoding="utf-8")
            (root / ".env").write_text(f'password = "{PASSWORD}"\n', encoding="utf-8")
            runner = FakeRunner({})
            plate = collect_secrets(runner, str(root), which=lambda _name: None)
            blob = json.dumps(plate.to_dict())
            self.assertEqual(runner.calls, [])
            self.assertEqual(plate.status, "broken")
            self.assertIn("ok.py", blob)
            self.assertIn("aws-access-key", blob)
            self.assertIn(".env", blob)
            self.assertIn("hardcoded-secret", blob)
            self.assertNotIn("secret.txt", blob)
            self.assertNotIn("skipme", blob)
            self.assertNotIn(".git", blob)
            for secret in (EXAMPLE_KEY, GITHUB, PASSWORD, PRIVATE, "not-a-real-key"):
                self.assertNotIn(secret, blob)
            rendered = render_text(
                collect_report(
                    {"secrets": {"path": str(root)}},
                    runner,
                    proc_reader=lambda: {},
                    log_reader=self._missing,
                    which=lambda _n: None,
                ),
                color=False,
            )
            self.assertIn(DISCLAIMER, rendered)
            for secret in (EXAMPLE_KEY, GITHUB, PASSWORD, PRIVATE):
                self.assertNotIn(secret, rendered)

    def test_scan_output_has_path_and_rule_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(f"# {EXAMPLE_KEY}\n", encoding="utf-8")
            plate = collect_secrets(FakeRunner({}), str(root), which=lambda _n: None)
            self.assertEqual(plate.evidence[0], "app.py:1 aws-access-key")
            self.assertNotIn(EXAMPLE_KEY, plate.evidence[0])

    def test_zero_hits_intact(self):
        with tempfile.TemporaryDirectory() as tmp:
            plate = collect_secrets(FakeRunner({}), tmp, which=lambda _n: None)
            self.assertEqual(plate.status, "intact")

    def test_missing_path_unknown(self):
        plate = collect_secrets(FakeRunner({}), "/tmp/shieldwall-missing-scan-path", which=lambda _n: None)
        self.assertEqual(plate.status, "unknown")
        self.assertNotEqual(plate.status, "intact")

    def test_secretsweep_json_strips_values(self):
        path = "/tmp/proj"
        payload = {
            "findings": [
                {
                    "path": "src/app.py",
                    "rule_id": "aws-access-key",
                    "line": 4,
                    "secret": EXAMPLE_KEY,
                    "match": "supersecretvalue",
                    "value": PASSWORD,
                }
            ]
        }
        argv = secretsweep_argv(path)
        runner = FakeRunner({tuple(argv): canned(argv, json.dumps(payload), returncode=1)})
        plate = collect_secrets(runner, path, which=lambda _n: "/usr/bin/secretsweep")
        blob = json.dumps(plate.to_dict())
        self.assertEqual(plate.status, "broken")
        self.assertIn("src/app.py:4 aws-access-key", plate.evidence)
        self.assertEqual(runner.calls, [tuple(argv)])
        self.assertEqual(argv, ["secretsweep", "scan", path, "--format", "json"])
        for secret in (EXAMPLE_KEY, "supersecretvalue", PASSWORD):
            self.assertNotIn(secret, blob)

    def test_secretsweep_parser_ignores_secret_fields(self):
        hits = parse_secretsweep(
            json.dumps([{"file": "a.env", "rule": "github-pat", "snippet": GITHUB}])
        )
        self.assertEqual(hits[0].path, "a.env")
        self.assertEqual(hits[0].rule_id, "github-pat")
        self.assertNotIn(GITHUB, hits[0].path + hits[0].rule_id)

    def test_secretsweep_bad_json_unknown(self):
        path = "."
        argv = secretsweep_argv(path)
        runner = FakeRunner({tuple(argv): canned(argv, "not-json", returncode=2)})
        plate = collect_secrets(runner, path, which=lambda _n: "/usr/bin/secretsweep")
        self.assertEqual(plate.status, "unknown")

    def test_argv_keeps_path_as_one_argument(self):
        argv = secretsweep_argv("my path; echo injected")
        self.assertEqual(
            argv,
            ["secretsweep", "scan", "my path; echo injected", "--format", "json"],
        )

    def _missing(self, _path):
        raise FileNotFoundError(_path)
