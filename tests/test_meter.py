import unittest

from shieldwall.meter import POINTS, armor_meter, meter_phrase
from shieldwall.model import DISCLAIMER


class MeterTests(unittest.TestCase):
    def test_all_intact_is_steel(self):
        meter = armor_meter(["intact"] * 5)
        self.assertEqual(meter.score, 100)
        self.assertEqual(meter.label, "steel")
        self.assertEqual(meter.disclaimer, DISCLAIMER)

    def test_scored_and_unknown_are_bone(self):
        scored = armor_meter(["scored"] * 5)
        self.assertEqual(scored.score, 50)
        self.assertEqual(scored.label, "bone")
        mixed = armor_meter(["intact", "intact", "intact", "intact", "unknown"])
        self.assertEqual(mixed.score, 80)
        self.assertEqual(mixed.label, "bone")
        self.assertNotEqual(mixed.label, "steel")

    def test_broken_forces_blood_even_when_score_is_high(self):
        meter = armor_meter(["intact", "broken", "scored", "scored", "intact"])
        self.assertEqual(meter.score, 60)
        self.assertEqual(meter.label, "blood")
        high = armor_meter(["intact", "intact", "intact", "intact", "broken"])
        self.assertEqual(high.score, 80)
        self.assertEqual(high.label, "blood")
        self.assertIn("plate broken", meter_phrase(high, ["intact"] * 4 + ["broken"]))

    def test_unknown_scores_zero_and_is_not_intact(self):
        meter = armor_meter(["unknown"] * 5)
        self.assertEqual(meter.score, 0)
        self.assertEqual(meter.label, "bone")
        self.assertEqual(POINTS["unknown"], 0)
        self.assertNotEqual(meter.label, "steel")

    def test_empty_is_not_steel(self):
        meter = armor_meter([])
        self.assertEqual(meter.score, 0)
        self.assertEqual(meter.label, "bone")

    def test_invalid_status(self):
        with self.assertRaises(ValueError):
            armor_meter(["healthy"])

    def test_phrase_plural(self):
        statuses = ["broken", "broken", "intact", "intact", "intact"]
        meter = armor_meter(statuses)
        self.assertIn("2 plates broken", meter_phrase(meter, statuses))
