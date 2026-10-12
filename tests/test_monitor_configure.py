import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONFIGURE = ROOT / "rootfs/usr/local/libexec/monitor-configure"


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.runtime = self.directory / "monitor"
        self.runtime.mkdir(mode=0o750)
        self.source = self.directory / "monitor.identity"
        self.route = {"domain": "personal.example", "ip": "100.64.0.1", "port": 18293,
                      "host_key": "ssh-ed25519 AAAA"}
        self.identity = "-----BEGIN PRIVATE KEY-----\nTEST\n"
        self.source.write_text(self.identity)

    def configure(self, boot=False):
        return subprocess.run([sys.executable, str(CONFIGURE), "--boot" if boot else str(self.source)],
                              env={**os.environ, "RUNTIME_DIRECTORY": str(self.runtime), "MONITOR_ROUTE": json.dumps(self.route)},
                              umask=0o027, capture_output=True, text=True, timeout=5)

    def ssh_config(self, name):
        template = (ROOT / "rootfs/etc/ssh" / name).read_text()
        config = self.directory / "ssh_config"
        config.write_text(template.replace("/run/monitor", str(self.runtime)))
        result = subprocess.run(["ssh", "-G", "-F", str(config), "monitor"],
                                capture_output=True, text=True, check=True, timeout=5)
        return result.stdout.splitlines()

    def test_routes_preserve_ssh_identities_host_pinning_and_fixed_forwards(self):
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        public = json.loads((self.runtime / "route.json").read_text())
        self.assertNotIn("identity", public)
        self.assertEqual(public["ip"], self.route["ip"])
        self.assertEqual((self.runtime / "identity").read_text(), self.identity)
        self.assertEqual((self.runtime / "known_hosts").read_text(), "monitor " + self.route["host_key"] + "\n")
        for file in self.runtime.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o640)

        agent = self.ssh_config("ssh_config.d/monitor.conf")
        network = self.ssh_config("monitor-network.conf")
        reverse = self.ssh_config("monitor-reverse.conf")
        for config in (agent, network, reverse):
            self.assertIn("hostname 100.64.0.1", config)
            self.assertIn("port 18293", config)
            self.assertIn("hostkeyalias monitor", config)
            self.assertIn("stricthostkeychecking true", config)
            self.assertIn("identitiesonly yes", config)
            self.assertIn("identityagent none", config)
            self.assertIn("userknownhostsfile " + str(self.runtime / "known_hosts"), config)
            self.assertIn("globalknownhostsfile /dev/null", config)
        self.assertIn("user monitor", agent)
        self.assertIn("identityfile " + str(self.runtime / "identity"), agent)
        self.assertIn("user monitor", network)
        # ssh -G prints environment references before connection-time expansion.
        self.assertIn("identityfile ${CREDENTIALS_DIRECTORY}/identity", network)
        # The measured owner public key is supplied with -l by the boot script/unit.
        self.assertIn("identityfile /run/workspace/host_key", reverse)
        self.assertIn("batchmode yes", reverse)
        self.assertIn("exitonforwardfailure yes", reverse)
        self.assertIn("connecttimeout 10", reverse)
        self.assertIn("serveraliveinterval 15", reverse)
        self.assertIn("serveralivecountmax 3", reverse)
        self.assertEqual([line.replace("[", "").replace("]", "")
                          for line in reverse if line.startswith("remoteforward ")],
                         ["remoteforward 127.0.0.1:22 127.0.0.1:22", "remoteforward 127.0.0.1:443 127.0.0.1:8443"])
        self.assertFalse(any(line.startswith("remoteforward ") for line in agent))

    def test_boot_route_needs_no_private_identity(self):
        self.source.unlink()
        result = self.configure(boot=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.runtime / "route.json").read_text()), self.route)
        self.assertFalse((self.runtime / "identity").exists())

    def test_missing_or_invalid_identity_cannot_supply_a_route(self):
        self.source.unlink()
        self.assertNotEqual(self.configure().returncode, 0)
        for value in ["", "null", json.dumps({**self.route, "identity": "bad"})]:
            self.source.write_text(value)
            self.assertNotEqual(self.configure().returncode, 0)
            self.assertEqual(list(self.runtime.iterdir()), [])

    def test_invalid_measured_route_fails_without_publishing(self):
        invalid = [None, {}, [], {**self.route, "identity": self.identity}]
        for field, values in {
            "ip": ["127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "garbage"],
            "port": [0, 65536, True, "22"],
            "domain": ["", "bad/name", "bad\nname"],
            "host_key": ["", "ssh-ed25519 AAAA\nother key"],
        }.items():
            invalid.extend({**self.route, field: value} for value in values)
        for value in invalid:
            with self.subTest(route=value):
                self.route = value
                self.assertNotEqual(self.configure().returncode, 0)
                self.assertEqual(list(self.runtime.iterdir()), [])

    def test_ipv4_mapped_route_is_normalized_for_ssh_and_tun(self):
        self.route["ip"] = "::ffff:100.64.0.1"
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.runtime / "route.json").read_text())["ip"], "100.64.0.1")
        self.assertIn("hostname 100.64.0.1", self.ssh_config("monitor-reverse.conf"))


if __name__ == "__main__":
    unittest.main()
