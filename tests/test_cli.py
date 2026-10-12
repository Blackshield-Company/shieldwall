import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from shieldwall.cli import main
from shieldwall.model import DISCLAIMER, PLATE_NAMES
from tests.fakes import FakeRunner, missing_log


class CLITests(unittest.TestCase):
    def test_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(
                    ["--json", "--secrets-path", tmp, "--no-color"],
                    runner=FakeRunner({}),
                    proc_reader=lambda: {},
                    log_reader=missing_log,
                    which=lambda _name: None,
                )
            self.assertEqual(code, 0)
            data = json.loads(out.getvalue())
            self.assertEqual([plate["name"] for plate in data["plates"]], list(PLATE_NAMES))
            self.assertEqual(data["disclaimer"], DISCLAIMER)
            self.assertTrue(data["read_only"])
            self.assertEqual(data["plates"][4]["status"], "intact")
            for plate in data["plates"][:4]:
                self.assertEqual(plate["status"], "unknown")
                self.assertNotEqual(plate["status"], "intact")

    def test_serve_refuses_non_loopback_host(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main(["serve", "--host", "0.0.0.0", "--port", "9"], runner=FakeRunner({}))
        self.assertEqual(code, 2)
        self.assertIn("refusing non-loopback", err.getvalue())

    def test_serve_refuses_config_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text('[serve]\nhost = "192.0.2.10"\nport = 8787\n', encoding="utf-8")
            err = io.StringIO()
            with redirect_stderr(err):
                code = main(["--config", str(path), "serve"], runner=FakeRunner({}))
            self.assertEqual(code, 2)
            self.assertIn("refusing non-loopback", err.getvalue())

    def test_text_no_color_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(
                    ["--no-color", "--secrets-path", tmp],
                    runner=FakeRunner({}),
                    proc_reader=lambda: {},
                    log_reader=missing_log,
                    which=lambda _name: None,
                )
            self.assertEqual(code, 0)
            text = out.getvalue()
            self.assertNotIn("\033", text)
            self.assertIn(DISCLAIMER, text)
            self.assertIn("SHIELDWALL", text)
