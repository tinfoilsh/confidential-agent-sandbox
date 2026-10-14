import ipaddress
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from test_workspace_route import helper


ROOT = Path(__file__).resolve().parents[1]


class NetworkIdentityTests(unittest.TestCase):
    def test_tunnel_does_not_require_ipv6_policy_routing(self):
        monitor = helper('monitor', 'rootfs/usr/local/bin/monitor')
        config = monitor.network_config(12345)
        for inbound in config['inbounds']:
            for address in inbound['address']:
                self.assertEqual(ipaddress.ip_interface(address).version, 4)
            self.assertIn('10.254.0.1/32', inbound['route_exclude_address'])
        self.assertEqual(config['dns']['rules'][0]['query_type'], ['A'])

    def test_service_and_user_share_the_current_private_identity(self):
        service = (ROOT / 'rootfs/etc/systemd/system/monitor-network.service').read_text()
        command = shlex.split(next(line.split('=', 1)[1] for line in service.splitlines() if line.startswith('ExecStart=')))
        config = ROOT / ('rootfs' + command[command.index('--ssh-config') + 1])
        self.assertEqual(config, ROOT / 'rootfs/etc/ssh/ssh_config.d/monitor.conf')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / 'identity'
            ssh_config = directory / 'ssh.conf'
            ssh_config.write_text(config.read_text().replace('/run/monitor', temporary))
            # Rotation needs no second identity file for root's network service.
            for attempt in range(2):
                with self.subTest(attempt=attempt):
                    source.unlink(missing_ok=True)
                    source.with_suffix('.pub').unlink(missing_ok=True)
                    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(source)], check=True)
                    source.chmod(0o600)
                    resolved = subprocess.check_output(['ssh', '-T', '-G', '-F', str(ssh_config), 'monitor'],
                                                       text=True)
                    self.assertIn('hostname 10.254.0.1\n', resolved)
                    self.assertIn('port 22\n', resolved)
                    identity = Path(next(line.split(' ', 1)[1] for line in resolved.splitlines()
                                         if line.startswith('identityfile ')))
                    self.assertEqual(identity, source)
                    self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
                    public = subprocess.check_output(['ssh-keygen', '-y', '-P', '', '-f', str(identity)], text=True)
                    self.assertEqual(public.split()[:2], source.with_suffix('.pub').read_text().split()[:2])
