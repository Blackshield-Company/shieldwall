import json
import threading
import time
import unittest
from urllib.error import URLError
from urllib.request import urlopen

from shieldwall.model import DISCLAIMER
from shieldwall.serve import (
    LoopbackRefusal,
    bind_host,
    ensure_loopback,
    host_header_ok,
    is_loopback_host,
    make_server,
    start_server,
)


def _get(url):
    last = None
    for _ in range(30):
        try:
            with urlopen(url, timeout=2) as resp:
                return resp.status, resp.read()
        except URLError as exc:
            last = exc
            time.sleep(0.05)
    raise last


class LoopbackTests(unittest.TestCase):
    def test_refuse_non_loopback(self):
        for host in ("0.0.0.0", "192.0.2.10", "198.51.100.1", "203.0.113.5", "example.com", "", "::"):
            with self.assertRaises(LoopbackRefusal):
                ensure_loopback(host)
            self.assertFalse(is_loopback_host(host))

    def test_allow_loopback(self):
        self.assertEqual(bind_host("localhost"), "127.0.0.1")
        self.assertEqual(bind_host(" 127.0.0.1 "), "127.0.0.1")
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("127.0.0.2"))

    def test_make_server_refuses_before_bind(self):
        with self.assertRaises(LoopbackRefusal):
            make_server("0.0.0.0", 9, lambda: {})
        with self.assertRaises(LoopbackRefusal):
            make_server("192.0.2.10", 9, lambda: {})


class ServeTests(unittest.TestCase):
    def test_ephemeral_port_html_and_api(self):
        report = {
            "host": "local",
            "read_only": True,
            "disclaimer": DISCLAIMER,
            "meter": {"score": 40, "label": "bone", "disclaimer": DISCLAIMER},
            "plates": [
                {
                    "name": "firewall",
                    "status": "unknown",
                    "headline": "unknown",
                    "detail": "no tool",
                    "evidence": ["no firewall tool found"],
                    "error": "no firewall tool found",
                }
            ],
        }
        httpd = start_server("127.0.0.1", 0, lambda: report)
        port = httpd.server_address[1]
        self.assertEqual(httpd.server_address[0], "127.0.0.1")
        self.assertGreater(port, 0)
        try:
            status, body = _get(f"http://127.0.0.1:{port}/api/plates")
            self.assertEqual(status, 200)
            data = json.loads(body.decode())
            self.assertEqual(data["disclaimer"], DISCLAIMER)
            self.assertEqual(data["meter"]["score"], 40)
            self.assertTrue(data["read_only"])
            status, page = _get(f"http://127.0.0.1:{port}/")
            self.assertEqual(status, 200)
            html = page.decode()
            self.assertIn("SHIELDWALL", html)
            self.assertIn(DISCLAIMER, html)
            self.assertIn("#8b0000", html)
            self.assertIn("FIREWALL", html)
        finally:
            httpd.shutdown()
            httpd.server_close()
            threading.Event().wait(0.05)


class HostHeaderTests(unittest.TestCase):
    def test_host_header_values(self):
        for ok in (None, "127.0.0.1", "127.0.0.1:8787", "localhost:8787", "LOCALHOST", "[::1]:8787", "[::1]"):
            self.assertTrue(host_header_ok(ok), ok)
        for bad in ("", "attacker.example", "attacker.example:8787", "192.0.2.10:80", "[::1]x",
                    "127.0.0.1:abc", "[2001:db8::1]:80", "::1"):
            self.assertFalse(host_header_ok(bad), bad)

    def test_rebound_host_is_refused(self):
        import http.client

        httpd = start_server("127.0.0.1", 0, lambda: {"host": "box", "plates": []})
        try:
            port = httpd.server_address[1]
            for path in ("/api/plates", "/"):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", path, headers={"Host": "attacker.example:%d" % port})
                resp = conn.getresponse()
                body = resp.read()
                conn.close()
                self.assertEqual(resp.status, 421, path)
                self.assertNotIn(b"plates", body)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/api/plates", headers={"Host": "localhost:%d" % port})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            resp.read()
            conn.close()
        finally:
            httpd.shutdown()
            httpd.server_close()
