import re
import unittest
from pathlib import Path


class OwnerTemplateTests(unittest.TestCase):
    def test_either_owner_binding_can_be_supplied_without_requiring_the_other(self):
        template = (Path(__file__).resolve().parents[1] / "tinfoil-config.yml").read_text()
        names = ("SANDBOX_OWNER_KEY_SHA256", "SANDBOX_OWNER_KEY_ARGON2ID")
        for name in names:
            entries = list(re.finditer(r"^\s+- " + name + r"(?:=(.*))?$", template, re.M))
            self.assertEqual(len(entries), 1, f"declare {name} once")
            self.assertEqual(entries[0].group(1), "", f"{name} needs an empty default, not a required placeholder")
