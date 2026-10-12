import os
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
        config = monitor.network_config(12345, '192.0.2.1')
        for inbound in config['inbounds']:
            for address in inbound['address']:
                self.assertEqual(ipaddress.ip_interface(address).version, 4)
        self.assertEqual(config['dns']['rules'][0]['query_type'], ['A'])

    def test_service_prepares_ssh_identity_without_systemd_credentials(self):
        service = (ROOT / 'rootfs/etc/systemd/system/monitor-network.service').read_text()
        config = (ROOT / 'rootfs/etc/ssh/monitor-network.conf').read_text()
        environment = {key: value for key, value in os.environ.items() if key != 'CREDENTIALS_DIRECTORY'}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / 'identity'
            ssh_config = directory / 'ssh.conf'
            (directory / 'endpoint.conf').write_text('HostName 192.0.2.1\nPort 2223\n')
            ssh_config.write_text(config.replace('/run/monitor', temporary))
            # Repeat after rotation: each service start must use the current key.
            for attempt in range(2):
                with self.subTest(attempt=attempt):
                    source.unlink(missing_ok=True)
                    source.with_suffix('.pub').unlink(missing_ok=True)
                    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(source)], check=True)
                    source.chmod(0o640)
                    for line in service.splitlines():
                        if line.startswith('ExecStartPre='):
                            subprocess.run(shlex.split(line.split('=', 1)[1].replace('/run/monitor', temporary)),
                                           check=True, env=environment)
                    resolved = subprocess.check_output(['ssh', '-T', '-G', '-F', str(ssh_config), 'monitor'],
                                                       env=environment, text=True)
                    identity = Path(next(line.split(' ', 1)[1] for line in resolved.splitlines()
                                         if line.startswith('identityfile ')))
                    self.assertEqual(identity.read_bytes(), source.read_bytes())
                    self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(source.stat().st_mode & 0o777, 0o640)
                    public = subprocess.check_output(['ssh-keygen', '-y', '-P', '', '-f', str(identity)], text=True)
                    self.assertEqual(public.split()[:2], source.with_suffix('.pub').read_text().split()[:2])
