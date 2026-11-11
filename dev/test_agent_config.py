import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SEED = runpy.run_path(str(ROOT / "rootfs/usr/local/libexec/seed-agent-config"))
URL = "https://tinfoil-websearch.perimeter/mcp"


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
        provider = tomllib.loads((self.home / ".codex/tinfoil.config.toml").read_text())
        self.assertEqual(provider["model_providers"]["tinfoil"]["base_url"], "https://tinfoil.perimeter/v1")
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
        codex = self.put(".codex/config.toml", '[mcp_servers.tinfoil_websearch]\nenabled = false\nurl = "http://custom.perimeter/mcp"\n')
        claude = self.put(".claude.json", json.dumps({"mcpServers": {"tinfoil_websearch": {"type": "http", "url": "http://custom.perimeter/mcp"}}}))
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

    def test_refresh_lists_served_models_as_data(self):
        marker = self.home / "executed"
        hostile = f"smart$(touch {marker})"
        payload = {"data": [
            {"id": "old", "type": "chat", "tool_calling": True, "deprecated": True, "context_window": 262144, "intelligence": {"on": 50}},
            {"id": "fast", "name": "Fast", "type": "chat", "tool_calling": True, "context_window": 131072, "intelligence": {"off": 10},
             "endpoints": ["/v1/chat/completions", "/v1/responses"]},
            {"id": hostile, "name": "Smart", "type": "chat", "tool_calling": True, "context_window": 1048576, "intelligence": {"high": 45},
             "endpoints": ["/v1/chat/completions"]},
            {"id": "preview", "type": "chat", "tool_calling": True, "experimental": True, "context_window": 262144, "intelligence": {"on": 46}},
            {"id": "embed", "type": "embedding", "context_window": 8192},
        ]}
        root = self.home / "rootfs"
        for relative in ("etc/opencode", "etc/crush", "etc/qwen-code", "usr/local/share/tinfoil"):
            shutil.copytree(ROOT / "rootfs" / relative, root / relative)
        claude = root / "usr/local/share/tinfoil/claude.json"
        claude.chmod(0o644)
        self.seed()
        codex = self.home / ".codex/tinfoil.config.toml"
        codex.write_text('model = "fast"\n' + codex.read_text())
        SEED["refresh"](self.home, payload, root)

        ids = [hostile, "fast", "preview"]
        opencode = json.loads((root / "etc/opencode/opencode.json").read_text())
        self.assertEqual(list(opencode["provider"]["tinfoil"]["models"]), ids)
        self.assertEqual(json.loads(claude.read_text())["env"]["ANTHROPIC_MODEL"], hostile)
        self.assertEqual(claude.stat().st_mode & 0o777, 0o644)
        tinfoil = root / "usr/local/share/tinfoil"
        script = (tinfoil / "copilot.env").read_text().replace("/usr/local/share/tinfoil/", f"{tinfoil}/")
        copilot = subprocess.run(["bash", "-c", script + 'printf "%s\\n" "$COPILOT_MODEL" "$COPILOT_PROVIDER_MAX_PROMPT_TOKENS"'],
                                 capture_output=True, text=True, check=True)
        self.assertEqual(copilot.stdout, f"{hostile}\n983040\n")
        self.assertFalse(marker.exists())
        profile = tomllib.loads(codex.read_text())
        self.assertEqual((profile["model"], profile["model_context_window"]), ("fast", 131072))
        pi = json.loads((self.home / ".pi/agent/models.json").read_text())
        self.assertEqual([m["id"] for m in pi["providers"]["tinfoil"]["models"]], ids)
        droid = json.loads((self.home / ".factory/settings.json").read_text())
        self.assertEqual([m["model"] for m in droid["customModels"]], ids)

        files = {p: p.read_bytes() for p in self.home.rglob("*") if p.is_file()}
        SEED["refresh"](self.home, payload, root)
        self.assertEqual(files, {p: p.read_bytes() for p in self.home.rglob("*") if p.is_file()})

    def test_no_monitor_does_not_install_perimeter_mcp(self):
        self.seed("1")
        self.assertFalse((self.home / ".claude.json").exists())
        self.assertFalse((self.home / ".codex/config.toml").exists())
        self.assertFalse((self.home / ".factory/mcp.json").exists())
        self.assertNotIn("mcp_servers", tomllib.loads((self.home / ".codex/tinfoil.config.toml").read_text()))


if __name__ == "__main__":
    unittest.main()
