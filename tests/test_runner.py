import unittest

from shieldwall.runner import Runner


class RunnerTests(unittest.TestCase):
    def test_missing_binary(self):
        result = Runner(timeout=2).run(["shieldwall-missing-bin-xyz"])
        self.assertTrue(result.not_found)
        self.assertIsNone(result.returncode)

    def test_timeout(self):
        result = Runner(timeout=0.4).run(["python3", "-c", "import time; time.sleep(3)"])
        self.assertTrue(result.timed_out)

    def test_no_shell_expansion(self):
        result = Runner(timeout=2).run(
            ["python3", "-c", "import sys; print(sys.argv[1])", "a; echo injected"]
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("a; echo injected", result.stdout)
        self.assertNotIn("injected", result.stdout.replace("a; echo injected", ""))
