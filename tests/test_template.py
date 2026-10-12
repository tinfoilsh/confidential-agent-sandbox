import re
import unittest
from pathlib import Path


class OwnerTemplateTests(unittest.TestCase):
    def test_owner_and_monitor_route_are_measured_defaults(self):
        template = (Path(__file__).resolve().parents[1] / "tinfoil-config.yml").read_text()
        for name in ("SANDBOX_OWNER_PUBLIC_KEY", "MONITOR_ROUTE"):
            entries = re.findall(r'^\s+- ' + name + r': (.*)$', template, re.M)
            self.assertEqual(entries, ['""'], f"{name} must have an explicit measured default")
        self.assertNotIn("/enroll", template)
        self.assertNotIn("/owner/challenge", template)
        self.assertNotIn("SANDBOX_OWNER_KEY_", template)
