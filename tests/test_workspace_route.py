import base64
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def helper(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


class RouteTests(unittest.TestCase):
    def setUp(self):
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.keys = helper('keys', 'rootfs/usr/local/libexec/workspace-keys')
        self.unlock = helper('unlock', 'rootfs/usr/local/bin/workspace-unlock')
        self.unlock.RUNTIME = self.directory / 'workspace'
        self.unlock.DISK = self.directory / 'disk'
        self.unlock.MONITOR = self.directory / 'monitor'
        for path in (self.unlock.RUNTIME, self.unlock.DISK):
            path.mkdir()
        self.owner = 'ed25519:' + base64.b64encode(bytes(range(32))).decode()
        self.binding = {'container_id': '11111111-1111-4111-8111-111111111111', 'owner_public_key': self.owner}
        self.environment = {'SANDBOX_OWNER_PUBLIC_KEY': self.owner,
                            'SANDBOX_INSTANCE_ID': '22222222-2222-4222-8222-222222222222',
                            'MONITOR_BINDING': json.dumps(self.binding)}
        self.key_path = self.directory / 'key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key_path)], check=True)
        self.public = self.key_path.with_suffix('.pub').read_text().strip()

    def test_boot_without_endpoint_stays_ready_for_owner_ssh(self):
        self.keys.prepare(self.unlock.RUNTIME, self.environment)
        self.assertTrue((self.unlock.RUNTIME / 'authorized_keys').exists())
        self.assertFalse((self.unlock.RUNTIME / 'monitor-bootstrap.conf').exists())
        self.assertFalse(self.unlock.MONITOR.exists())

    def test_endpoint_cannot_inject_ssh_options(self):
        for endpoint in ('127.0.0.1:22', '169.254.1.1:22', '1.2.3.4:0', '1.2.3.4:65536', '1.2.3.4\nProxyCommand evil:22'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                self.keys.prepare(self.unlock.RUNTIME, {**self.environment, 'MONITOR_ENDPOINT': endpoint})
        self.assertFalse((self.unlock.RUNTIME / 'monitor-bootstrap.conf').exists())

    def test_monitor_reboot_refreshes_route_without_touching_disk_keys(self):
        self.keys.prepare(self.unlock.RUNTIME, {**self.environment, 'MONITOR_ENDPOINT': '100.64.0.1:2222'})
        (self.unlock.RUNTIME / 'host_key.pub').write_text(self.public + '\n')
        receipt = (self.public + '\nunchanged credentials\n').encode()
        (self.unlock.DISK / '.enrollment').write_bytes(receipt)
        (self.unlock.DISK / '.monitor.identity').write_bytes(self.key_path.read_bytes())
        request = {'operation': 'route', 'monitor_route': {'binding': self.binding, 'host_key': self.public}}
        run = subprocess.run
        def child(command, **kwargs):
            if command[0] == '/usr/bin/systemctl':
                self.assertEqual(command[1:], ['restart', 'monitor-network.service'])
                return SimpleNamespace(returncode=0)
            return run(command, **kwargs)
        with patch.object(self.unlock, 'control', side_effect=AssertionError('route refresh opened disk')), \
             patch.object(self.unlock.subprocess, 'run', side_effect=child), \
             patch.object(self.unlock.os, 'chown'), \
             patch.object(self.unlock.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=os.getgid())):
            self.unlock.unlock(io.BytesIO(json.dumps(request).encode()))
            next_key = self.directory / 'next_key'
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(next_key)], check=True)
            self.public = next_key.with_suffix('.pub').read_text().strip()
            request['monitor_route']['host_key'] = self.public
            self.unlock.unlock(io.BytesIO(json.dumps(request).encode()))
            self.unlock.unlock(io.BytesIO(json.dumps(request).encode()))
            self.assertEqual(self.unlock.MONITOR.stat().st_mode & 0o777, 0o750)
            self.assertEqual((self.unlock.MONITOR / 'known_hosts').stat().st_mode & 0o777, 0o640)
            self.assertEqual((self.unlock.MONITOR / 'known_hosts').read_text(), 'monitor ' + self.public + '\n')
            self.assertEqual((self.unlock.DISK / '.enrollment').read_bytes(), receipt)
            before = (self.unlock.MONITOR / 'known_hosts').read_bytes()
            request['monitor_route']['binding'] = {**self.binding, 'container_id': 'another-monitor'}
            with self.assertRaisesRegex(ValueError, 'binding'):
                self.unlock.unlock(io.BytesIO(json.dumps(request).encode()))
            self.assertEqual((self.unlock.MONITOR / 'known_hosts').read_bytes(), before)

    def test_unlock_never_formats_and_initialization_retries_same_credentials(self):
        request = {'operation': 'unlock', 'volume': base64.b64encode(bytes(range(32))).decode(),
                   'monitor_identity': self.key_path.read_text()}
        boot = (self.public + '\n').encode()
        with patch.object(self.unlock, 'control', return_value=b'rejected') as worker:
            with self.assertRaisesRegex(ValueError, 'workspace unlock request rejected'):
                self.unlock.open_workspace(request, boot)
            self.assertEqual([call.args[0] for call in worker.call_args_list], [b'u'])
        self.assertFalse((self.unlock.RUNTIME / 'unlock.intent').exists())
        request['operation'] = 'initialize'
        # Keep the control socket logically present for the first attempt.
        self.unlock.CONTROL = str(self.key_path)
        with patch.object(self.unlock, 'control', side_effect=[b'rejected', b'ok']) as worker, \
             patch.object(Path, 'is_mount', return_value=True):
            receipt = self.unlock.open_workspace(request, boot)
            self.assertEqual([call.args[0] for call in worker.call_args_list], [b'i', b'u'])
        with patch.object(self.unlock, 'control', side_effect=AssertionError('retried volume worker')):
            self.assertEqual(self.unlock.open_workspace(request, boot), receipt)
            request['volume'] = base64.b64encode(bytes(32)).decode()
            with self.assertRaisesRegex(ValueError, 'another unlock'):
                self.unlock.open_workspace(request, boot)

    def test_initialization_handles_a_blank_disk_without_an_encryption_header(self):
        request = {'operation': 'initialize', 'volume': base64.b64encode(bytes(range(32))).decode(),
                   'monitor_identity': self.key_path.read_text()}
        self.unlock.CONTROL = str(self.key_path)
        # Match the worker: unlocking a blank disk fails; initializing it works.
        def response(operation, _key):
            return b'ok' if operation == b'i' else b'failed'
        with patch.object(self.unlock, 'control', side_effect=response) as worker, \
             patch.object(Path, 'is_mount', return_value=True):
            self.unlock.open_workspace(request, (self.public + '\n').encode())
        self.assertEqual([call.args[0] for call in worker.call_args_list], [b'i'])
        self.assertTrue((self.unlock.DISK / '.monitor.identity').exists())

    def test_failed_unlock_of_existing_workspace_does_not_initialize(self):
        request = {'operation': 'unlock', 'volume': base64.b64encode(bytes(range(32))).decode(),
                   'monitor_identity': self.key_path.read_text()}
        self.unlock.CONTROL = str(self.key_path)
        with patch.object(self.unlock, 'control', return_value=b'failed') as worker:
            with self.assertRaisesRegex(ValueError, 'workspace unlock failed in the volume worker'):
                self.unlock.open_workspace(request, (self.public + '\n').encode())
        self.assertEqual([call.args[0] for call in worker.call_args_list], [b'u'])
        self.assertFalse((self.unlock.RUNTIME / 'unlock.intent').exists())

    def test_initialization_preserves_the_workers_nonblank_disk_rejection(self):
        request = {'operation': 'initialize', 'volume': base64.b64encode(bytes(range(32))).decode(),
                   'monitor_identity': self.key_path.read_text()}
        self.unlock.CONTROL = str(self.key_path)
        with patch.object(self.unlock, 'control', side_effect=[b'rejected', b'failed']) as worker:
            with self.assertRaisesRegex(ValueError, 'workspace unlock failed in the volume worker'):
                self.unlock.open_workspace(request, (self.public + '\n').encode())
        self.assertEqual([call.args[0] for call in worker.call_args_list], [b'i', b'u'])
        self.assertFalse((self.unlock.RUNTIME / 'unlock.opened').exists())
        self.assertFalse((self.unlock.DISK / '.monitor.identity').exists())

    def test_initialization_worker_failure_is_reported_without_another_operation(self):
        request = {'operation': 'initialize', 'volume': base64.b64encode(bytes(range(32))).decode(),
                   'monitor_identity': self.key_path.read_text()}
        self.unlock.CONTROL = str(self.key_path)
        with patch.object(self.unlock, 'control', return_value=b'failed') as worker:
            with self.assertRaisesRegex(ValueError, 'workspace initialization failed in the volume worker'):
                self.unlock.open_workspace(request, (self.public + '\n').encode())
        self.assertEqual([call.args[0] for call in worker.call_args_list], [b'i'])
        self.assertFalse((self.unlock.RUNTIME / 'unlock.intent').exists())

    def test_lost_worker_reply_keeps_credentials_fixed_until_mount_is_confirmed(self):
        request = {'operation': 'initialize', 'volume': base64.b64encode(bytes(range(32))).decode(),
                   'monitor_identity': self.key_path.read_text()}
        boot = (self.public + '\n').encode()
        self.unlock.CONTROL = str(self.key_path)
        with patch.object(self.unlock, 'control', side_effect=OSError('reply lost')):
            with self.assertRaisesRegex(OSError, 'reply lost'):
                self.unlock.open_workspace(request, boot)
        self.assertTrue((self.unlock.RUNTIME / 'unlock.intent').exists())
        with patch.object(self.unlock, 'control', side_effect=AssertionError('changed credentials reached worker')):
            with self.assertRaisesRegex(ValueError, 'another unlock request is pending'):
                self.unlock.open_workspace({**request, 'volume': base64.b64encode(bytes(32)).decode()}, boot)
        self.unlock.CONTROL = str(self.directory / 'removed.sock')
        with patch.object(Path, 'is_mount', return_value=True), \
             patch.object(self.unlock, 'control', side_effect=AssertionError('retried completed worker')):
            self.unlock.open_workspace(request, boot)
        self.assertTrue((self.unlock.RUNTIME / 'unlock.opened').exists())

    def test_interrupted_identity_write_resumes_without_reopening_volume(self):
        request = {'operation': 'initialize', 'volume': base64.b64encode(bytes(range(32))).decode(),
                   'monitor_identity': self.key_path.read_text()}
        boot = (self.public + '\n').encode()
        self.unlock.CONTROL = str(self.key_path)
        save = self.unlock.save
        def interrupted(path, data):
            if path == self.unlock.DISK / '.monitor.identity':
                raise OSError('write interrupted')
            save(path, data)
        with patch.object(self.unlock, 'control', return_value=b'ok'), \
             patch.object(Path, 'is_mount', return_value=True), \
             patch.object(self.unlock, 'save', side_effect=interrupted):
            with self.assertRaisesRegex(OSError, 'write interrupted'):
                self.unlock.open_workspace(request, boot)
        with patch.object(self.unlock, 'control', side_effect=AssertionError('retried completed worker')):
            self.unlock.open_workspace(request, boot)
        self.assertEqual((self.unlock.DISK / '.monitor.identity').read_text(), request['monitor_identity'])

    def test_invalid_agent_identity_never_reaches_volume_worker(self):
        request = {'operation': 'initialize', 'volume': base64.b64encode(bytes(range(32))).decode(),
                   'monitor_identity': 'not a private key'}
        with patch.object(self.unlock, 'control', side_effect=AssertionError('invalid identity reached worker')):
            with self.assertRaisesRegex(ValueError, 'invalid Monitor agent identity'):
                self.unlock.open_workspace(request, (self.public + '\n').encode())
        self.assertFalse((self.unlock.RUNTIME / 'unlock.intent').exists())

    def test_only_bootstrap_is_permissive_and_only_fixed_ports_are_published(self):
        self.keys.prepare(self.unlock.RUNTIME, {**self.environment, 'MONITOR_ENDPOINT': '100.64.0.1:2222'})
        for name, strict in [('monitor-reverse.conf', 'false'), ('monitor-network.conf', 'true'), ('ssh_config.d/monitor.conf', 'true')]:
            template = (ROOT / 'rootfs/etc/ssh' / name).read_text()
            config = self.directory / 'ssh_config'
            config.write_text(template.replace('/run/workspace', str(self.unlock.RUNTIME)))
            lines = subprocess.check_output(['ssh', '-G', '-F', str(config), 'monitor'], text=True).splitlines()
            self.assertIn('stricthostkeychecking ' + strict, lines)
            self.assertIn('identityagent none', lines)
            forwards = [line for line in lines if line.startswith('remoteforward ')]
            self.assertEqual(len(forwards), 2 if strict == 'false' else 0)
            if strict == 'false':
                self.assertIn('userknownhostsfile /dev/null', lines)
                self.assertIn('user sandbox-v2:' + self.environment['SANDBOX_INSTANCE_ID'], lines)
                self.assertIn('forwardagent no', lines)


if __name__ == '__main__':
    unittest.main()
