import re
import unittest
from pathlib import Path


class OwnerTemplateTests(unittest.TestCase):
    def test_identities_are_measured_and_only_endpoint_is_runtime(self):
        template = (Path(__file__).resolve().parents[1] / "tinfoil-config.yml").read_text()
        for name in ("SANDBOX_OWNER_PUBLIC_KEY", "SANDBOX_INSTANCE_ID", "MONITOR_BINDING"):
            entries = re.findall(r'^\s+- ' + name + r': (.*)$', template, re.M)
            self.assertEqual(entries, ['""'], f"{name} must have an explicit measured default")
        self.assertRegex(template, r"(?m)^      - MONITOR_ENDPOINT$")
        self.assertNotIn("MONITOR_ROUTE", template)
        self.assertNotIn("/enroll", template)
        self.assertNotIn("/owner/challenge", template)
        self.assertNotIn("SANDBOX_OWNER_KEY_", template)
