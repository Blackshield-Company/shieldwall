import unittest

from shieldwall.meter import armor_meter
from shieldwall.model import DISCLAIMER, Plate, Report
from shieldwall.render import render_text


def _report():
    plates = [
        Plate("firewall", "intact", ["nft input policy drop"], headline="nft enabled", detail="drop in"),
        Plate("ports", "broken", ["tcp :443 0.0.0.0 caddy not in allowlist"], headline="2 listen", detail=":443 ?"),
        Plate("ssh", "scored", ["failed: 1", "accepted 192.0.2.10"], headline="1 failed", detail="192.0.2.10"),
        Plate("updates", "scored", ["12 pending via apt"], headline="12 pending", detail="apt"),
        Plate("secrets", "intact", ["no hits in ."], headline="0 hits", detail="."),
    ]
    return Report("local", plates, armor_meter([plate.status for plate in plates]))


class RenderTests(unittest.TestCase):
    def test_one_screen_contains_plates_and_disclaimer(self):
        text = render_text(_report(), color=False)
        self.assertIn("SHIELDWALL", text)
        self.assertIn("ARMOR", text)
        self.assertIn(DISCLAIMER, text)
        self.assertIn("no changes will be applied from this screen", text)
        for name in ("FIREWALL", "PORTS", "SSH", "UPDATES", "SECRETS"):
            self.assertIn(name, text)
        self.assertIn("[broken]", text)
        self.assertIn("blood", text)
        self.assertNotIn("\033", text)

    def test_color_uses_blackshield_blood(self):
        text = render_text(_report(), color=True)
        self.assertIn("\033[38;2;139;0;0m", text)
        self.assertIn("\033[38;2;140;156;168m", text)
        self.assertIn("\033[38;2;232;220;196m", text)
        self.assertIn(DISCLAIMER, text)
