import contextlib
import io
import json
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = runpy.run_path(str(ROOT / "rootfs/usr/local/libexec/seed-agent-config"))["seed"]
TEMPLATES = ROOT / "rootfs/usr/local/share/tinfoil"
LEGACY = ROOT / "tests/fixtures/agent-config-v0.1.17"


class AgentConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def seed(self):
        SEED(self.home, TEMPLATES)

    def write(self, name, value):
        path = self.home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return path

    def snapshot(self):
        return {
            str(p.relative_to(self.home)): p.read_bytes()
            for p in self.home.rglob("*")
            if p.is_file()
        }

    def test_fresh_home_adds_options_without_default_selection(self):
        self.seed()
        self.assertEqual(
            set(self.snapshot()),
            {
                ".codex/tinfoil.config.toml",
                ".config/goose/custom_providers/tinfoil.json",
                ".pi/agent/models.json",
                ".factory/settings.json",
            },
        )
        for name, key in (
            (".pi/agent/models.json", "providers"),
            (".factory/settings.json", "customModels"),
        ):
            self.assertEqual(set(json.loads((self.home / name).read_text())), {key})
        first = self.snapshot()
        self.seed()
        self.assertEqual(self.snapshot(), first)

    def test_user_models_credentials_and_preferences_survive(self):
        pi = self.write(
            ".pi/agent/models.json", {"providers": {"other": {"apiKey": "user-key"}}}
        )
        custom = {
            "model": "user-model",
            "baseUrl": "https://user.example/v1",
            "apiKey": "user-key",
        }
        droid = self.write(
            ".factory/settings.json", {"model": "user-model", "customModels": [custom]}
        )
        codex = self.home / ".codex/config.toml"
        codex.parent.mkdir()
        codex.write_text('model = "user-model"\n')
        self.seed()
        self.assertEqual(
            json.loads(pi.read_text())["providers"]["other"], {"apiKey": "user-key"}
        )
        self.assertEqual(json.loads(droid.read_text())["model"], "user-model")
        self.assertEqual(json.loads(droid.read_text())["customModels"][0], custom)
        self.assertEqual(codex.read_text(), 'model = "user-model"\n')
        first = self.snapshot()
        self.seed()
        self.assertEqual(self.snapshot(), first)

    def test_user_tinfoil_connection_is_not_overwritten(self):
        pi = self.write(
            ".pi/agent/models.json", {"providers": {"tinfoil": {"apiKey": "custom"}}}
        )
        custom = json.loads((TEMPLATES / "droid.json").read_text())
        custom["customModels"][0]["apiKey"] = "custom"
        droid = self.write(".factory/settings.json", custom)
        originals = {p: p.read_bytes() for p in (pi, droid)}
        self.seed()
        for path, content in originals.items():
            self.assertEqual(path.read_bytes(), content)

    def test_only_untouched_v0_1_17_defaults_are_removed(self):
        shutil.copytree(LEGACY, self.home, dirs_exist_ok=True)
        self.seed()
        for old in LEGACY.rglob("*"):
            if old.is_file():
                self.assertFalse((self.home / old.relative_to(LEGACY)).exists())

    def test_edited_v0_1_17_defaults_are_preserved(self):
        shutil.copytree(LEGACY, self.home, dirs_exist_ok=True)
        for path in self.home.rglob("*"):
            if path.is_file():
                path.write_bytes(path.read_bytes() + b"\n")
        originals = self.snapshot()
        self.seed()
        for relative, content in originals.items():
            self.assertEqual((self.home / relative).read_bytes(), content)

    def test_invalid_or_linked_user_config_does_not_break_boot(self):
        pi = self.write(".pi/agent/models.json", {})
        pi.write_text('{"providers":')
        target = self.write("linked-settings.json", {"theme": "light"})
        droid = self.home / ".factory/settings.json"
        droid.parent.mkdir()
        droid.symlink_to(target)
        with contextlib.redirect_stderr(io.StringIO()):
            self.seed()
        self.assertEqual(pi.read_text(), '{"providers":')
        self.assertTrue(droid.is_symlink())
        self.assertEqual(json.loads(target.read_text()), {"theme": "light"})
