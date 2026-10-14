import base64
from concurrent.futures import ThreadPoolExecutor
import importlib.machinery
import importlib.util
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def helper(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.keys = helper('keys', 'rootfs/usr/local/libexec/workspace-keys')
        self.unlock = helper('unlock', 'rootfs/usr/local/bin/workspace-unlock')
        self.unlock.CONTROL = str(self.directory / 'control.sock')
        self.environment = {
            'SANDBOX_OWNER_PUBLIC_KEY': 'ed25519:' + base64.b64encode(bytes(range(32))).decode(),
            'SANDBOX_INSTANCE_ID': '22222222-2222-4222-8222-222222222222',
        }

    def exchange(self, key, initialize, replies):
        packets = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener, ThreadPoolExecutor(max_workers=1) as pool:
            listener.bind(self.unlock.CONTROL)
            listener.listen(1)
            listener.settimeout(5)
            def worker():
                for reply in replies:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(5)
                        packets.append(connection.recv(65537))
                        if reply is not None:
                            connection.sendall(reply)
            served = pool.submit(worker)
            try:
                if replies[-1] == b'ok':
                    self.unlock.unlock(key, initialize)
                else:
                    with self.assertRaisesRegex(ValueError, 'volume worker answered'):
                        self.unlock.unlock(key, initialize)
            finally:
                served.result(timeout=5)
                Path(self.unlock.CONTROL).unlink()
        return packets

    def test_key_bytes_are_forwarded_unchanged(self):
        for key in (b'short', bytes(range(32)), bytes(range(64)), bytes(range(256)) * 4):
            with self.subTest(length=len(key)):
                self.assertEqual(self.exchange(key, False, [b'ok']), [b'\x02u' + key])

    def test_initialize_only_falls_back_to_unlock_when_worker_rejects_it(self):
        key = b'a workspace passphrase of any supported length'
        self.assertEqual(self.exchange(key, True, [b'ok']), [b'\x02i' + key])
        self.assertEqual(self.exchange(key, True, [b'rejected', b'ok']), [b'\x02i' + key, b'\x02u' + key])

    def test_failures_do_not_retry_or_initialize_an_existing_disk(self):
        for initialize in (False, True):
            for reply in (b'failed', None):
                with self.subTest(initialize=initialize, reply=reply):
                    packet = b'\x02' + (b'i' if initialize else b'u') + b'key'
                    self.assertEqual(self.exchange(b'key', initialize, [reply]), [packet])
        self.assertEqual(self.exchange(b'key', False, [b'rejected']), [b'\x02ukey'])

    def test_missing_socket_does_not_claim_the_key_was_accepted(self):
        with self.assertRaises(FileNotFoundError):
            self.unlock.unlock(b'key')

    def test_bootstrap_needs_only_owner_and_instance(self):
        self.keys.prepare(self.directory, self.environment)
        self.assertEqual((self.directory / 'authorized_keys').read_text(),
                         self.keys.owner_key(self.environment['SANDBOX_OWNER_PUBLIC_KEY']))
        self.assertEqual((self.directory / 'monitor-bootstrap.conf').read_text(),
                         'User sandbox-v2:' + self.environment['SANDBOX_INSTANCE_ID'] + '\n')

    def test_only_bootstrap_is_permissive_and_all_connections_use_the_fixed_ip(self):
        self.keys.prepare(self.directory, self.environment)
        for name, strict in [('monitor-reverse.conf', 'false'), ('ssh_config.d/monitor.conf', 'true')]:
            template = (ROOT / 'rootfs/etc/ssh' / name).read_text()
            config = self.directory / 'ssh_config'
            config.write_text(template.replace('/run/workspace', str(self.directory)))
            lines = subprocess.check_output(['ssh', '-G', '-F', str(config), 'monitor'], text=True).splitlines()
            self.assertIn('stricthostkeychecking ' + strict, lines)
            self.assertIn('identityagent none', lines)
            self.assertIn('hostname 10.254.0.1', lines)
            self.assertIn('port 22', lines)
            forwards = [line for line in lines if line.startswith('remoteforward ')]
            self.assertEqual(len(forwards), 2 if strict == 'false' else 0)
            if strict == 'false':
                self.assertIn('userknownhostsfile /dev/null', lines)
                self.assertIn('user sandbox-v2:' + self.environment['SANDBOX_INSTANCE_ID'], lines)
                self.assertIn('forwardagent no', lines)


if __name__ == '__main__':
    unittest.main()
