from pathlib import Path
import runpy
import socket
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Worker:
    """Answers the volume control socket like the CVM worker, recording each request."""

    def __init__(self, path, answers):
        self.requests = []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.server.bind(str(path))
        self.server.listen()
        self.thread = threading.Thread(target=self.serve, args=(list(answers),), daemon=True)
        self.thread.start()

    def serve(self, answers):
        for answer in answers:
            connection, _ = self.server.accept()
            with connection:
                self.requests.append(connection.recv(256))
                connection.sendall(answer)

    def close(self):
        self.thread.join(5)
        self.server.close()


class WorkspaceUnlockTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # run_path returns a copy, so patch the globals the functions read.
        self.script = runpy.run_path(str(ROOT / "rootfs/usr/local/bin/workspace-unlock"))["unlock"].__globals__
        self.control = Path(self.temp.name) / "control.sock"
        self.script["CONTROL"] = str(self.control)
        self.mounted = False
        self.script["unlocked"] = lambda: self.mounted

    def worker(self, *answers):
        worker = Worker(self.control, answers)
        self.addCleanup(worker.close)
        return worker

    def test_status_reports_only_what_the_worker_or_mount_proves(self):
        for answer, state in [(b"blank", "locked_blank"), (b"used", "locked_initialized"), (b"failed", "locked_unknown"), (b"rejected", "locked_unknown")]:
            with self.subTest(answer=answer):
                worker = self.worker(answer)
                self.assertEqual(self.script["status"](), state)
                worker.close()
                self.assertEqual(worker.requests, [b"\x02s"])
                self.control.unlink()
        # A missing socket is never evidence of an unused disk.
        self.assertEqual(self.script["status"](), "locked_unknown")
        self.mounted = True
        self.assertEqual(self.script["status"](), "unlocked")

    def test_initialize_falls_back_to_unlock_on_a_used_disk(self):
        worker = self.worker(b"rejected", b"ok")
        self.script["unlock"](b"k" * 32, initialize=True)
        worker.close()
        self.assertEqual(worker.requests, [b"\x02i" + b"k" * 32, b"\x02u" + b"k" * 32])

    def test_lost_reply_reconciles_with_the_mount(self):
        with self.assertRaises(OSError):
            self.script["unlock"](b"k" * 32)
        self.mounted = True
        self.script["unlock"](b"k" * 32)

    def test_failed_unlock_is_an_error(self):
        self.worker(b"failed")
        with self.assertRaises(ValueError):
            self.script["unlock"](b"k" * 32)

    def test_queued_unlock_reset_requires_a_writable_mount(self):
        for error in (ConnectionResetError, BrokenPipeError):
            with self.subTest(error=error):
                def disconnected(*args, **kwargs):
                    raise error("worker stopped after opening the workspace")
                self.script["ask"] = disconnected
                self.mounted = False
                with self.assertRaises(error):
                    self.script["unlock"](b"k" * 32)
                self.mounted = True
                self.script["unlock"](b"k" * 32)

    def test_empty_reply_requires_a_writable_mount(self):
        self.script["ask"] = lambda *args, **kwargs: b""
        with self.assertRaises(ValueError):
            self.script["unlock"](b"k" * 32)
        self.mounted = True
        self.script["unlock"](b"k" * 32)


if __name__ == "__main__":
    unittest.main()
