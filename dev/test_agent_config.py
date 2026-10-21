import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SEED = runpy.run_path(str(ROOT / "rootfs/usr/local/libexec/seed-agent-config"))
URL = "http://tinfoil-websearch.monitor/mcp"


class AgentConfigTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def seed(self, no_monitor=""):
        with patch.dict(os.environ, {"NO_MONITOR": no_monitor}):
            SEED["seed"](self.home, ROOT / "rootfs/usr/local/share/tinfoil")

    def put(self, name, text):
        path = self.home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_fresh_home_and_repeat_boot(self):
        self.seed()
        codex = tomllib.loads((self.home / ".codex/config.toml").read_text())
        self.assertEqual(codex["mcp_servers"]["tinfoil_websearch"]["url"], URL)
        self.assertNotIn("model_provider", codex)
        for name in (".claude.json", ".factory/mcp.json"):
            cfg = json.loads((self.home / name).read_text())
            self.assertEqual(cfg["mcpServers"]["tinfoil_websearch"], {"type": "http", "url": URL})
        cfg = json.loads((self.home / ".config/opencode/opencode.json").read_text())
        self.assertEqual(cfg["mcp"]["tinfoil_websearch"]["url"], URL)
        files = {p: p.read_bytes() for p in self.home.rglob("*") if p.is_file()}
        self.seed()
        self.assertEqual(files, {p: p.read_bytes() for p in self.home.rglob("*") if p.is_file()})

    def test_preserves_provider_comments_and_other_mcp_servers(self):
        original = '# keep this comment\nmodel_provider = "my-provider"\n[mcp_servers.docs]\nurl = "https://example.com"\n'
        path = self.put(".codex/config.toml", original)
        self.put(".claude.json", json.dumps({"theme": "dark", "mcpServers": {"docs": {"type": "http", "url": "https://example.com"}}}))
        self.seed()
        self.assertTrue(path.read_text().startswith(original))
        cfg = json.loads((self.home / ".claude.json").read_text())
        self.assertEqual(cfg["theme"], "dark")
        self.assertIn("docs", cfg["mcpServers"])

    def test_preserves_disabled_and_custom_search_settings(self):
        codex = self.put(".codex/config.toml", '[mcp_servers.tinfoil_websearch]\nenabled = false\nurl = "http://custom.monitor/mcp"\n')
        claude = self.put(".claude.json", json.dumps({"mcpServers": {"tinfoil_websearch": {"type": "http", "url": "http://custom.monitor/mcp"}}}))
        original = {p: p.read_bytes() for p in (codex, claude)}
        self.seed()
        self.assertEqual(original, {p: p.read_bytes() for p in original})

    def test_preserves_invalid_files_and_symlinks(self):
        invalid = self.put(".codex/config.toml", "not valid TOML!")
        target = self.put("original.json", '{"untouched": true}')
        (self.home / ".claude.json").symlink_to(target)
        with contextlib.redirect_stderr(io.StringIO()):
            self.seed()
        self.assertEqual(invalid.read_text(), "not valid TOML!")
        self.assertTrue((self.home / ".claude.json").is_symlink())
        self.assertEqual(target.read_text(), '{"untouched": true}')

    def test_no_monitor_does_not_install_monitor_mcp(self):
        self.seed("1")
        self.assertFalse((self.home / ".claude.json").exists())
        self.assertFalse((self.home / ".codex/config.toml").exists())
        self.assertFalse((self.home / ".factory/mcp.json").exists())
        self.assertNotIn("mcp_servers", tomllib.loads((self.home / ".codex/tinfoil.config.toml").read_text()))


if __name__ == "__main__":
    unittest.main()
