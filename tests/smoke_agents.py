"""Exercise installed agents with disposable homes and a local inference server.

Run: python3 tests/smoke_agents.py --bin-dir /nix/var/nix/profiles/default/bin
No real credentials or inference services are used. The test checks provider
loading, endpoint, model, bearer authentication, and a complete text response.
It does not test Monitor attestation, policy, or upstream model behavior.
"""

import argparse
import json
import os
import runpy
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "rootfs/usr/local/share/tinfoil"
TOKEN = "tfm_tinfoil_TINFOIL_API_KEY"
REPLY = "TINFOIL_SMOKE_OK"
AGENTS = [
    "claude",
    "codex",
    "opencode",
    "crush",
    "qwen",
    "pi",
    "goose",
    "copilot",
    "droid",
]


def smoke(name, binary, system_configs=False):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, body, content_type="application/json"):
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.respond(
                json.dumps(
                    {"object": "list", "data": [{"id": "kimi-k3", "object": "model"}]}
                )
            )

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            request = json.loads(body)
            requests.append((self.path, dict(self.headers), request))
            if "count_tokens" in self.path:
                self.respond('{"input_tokens": 1}')
                return
            events = []
            if "/messages" in self.path:
                message = {
                    "id": "msg_smoke",
                    "type": "message",
                    "role": "assistant",
                    "model": "kimi-k3",
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
                events = [
                    {"type": "message_start", "message": message},
                    {
                        "type": "content_block_start",
                        "index": 0,
                        "content_block": {"type": "text", "text": ""},
                    },
                    {
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": REPLY},
                    },
                    {"type": "content_block_stop", "index": 0},
                    {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                        "usage": {"output_tokens": 1},
                    },
                    {"type": "message_stop"},
                ]
            elif "/responses" in self.path:
                item = {
                    "id": "msg_smoke",
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [
                        {"type": "output_text", "text": REPLY, "annotations": []}
                    ],
                }
                response = {
                    "id": "resp_smoke",
                    "object": "response",
                    "model": "kimi-k3",
                    "status": "completed",
                    "output": [item],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                }
                events = [
                    {
                        "type": "response.created",
                        "response": {**response, "status": "in_progress", "output": []},
                    },
                    {
                        "type": "response.output_item.added",
                        "output_index": 0,
                        "item": {**item, "status": "in_progress", "content": []},
                    },
                    {
                        "type": "response.output_text.delta",
                        "item_id": "msg_smoke",
                        "output_index": 0,
                        "content_index": 0,
                        "delta": REPLY,
                    },
                    {
                        "type": "response.output_item.done",
                        "output_index": 0,
                        "item": item,
                    },
                    {"type": "response.completed", "response": response},
                ]
            else:
                completion = {
                    "id": "chatcmpl_smoke",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": "kimi-k3",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": REPLY},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                }
                if not request.get("stream"):
                    self.respond(json.dumps(completion))
                    return
                events = [
                    {
                        **completion,
                        "object": "chat.completion.chunk",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"role": "assistant", "content": REPLY},
                                "finish_reason": None,
                            }
                        ],
                    },
                    {
                        **completion,
                        "object": "chat.completion.chunk",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    },
                ]
            stream = "".join(
                (f"event: {e['type']}\n" if "type" in e else "")
                + "data: "
                + json.dumps(e)
                + "\n\n"
                for e in events
            )
            if "/chat/completions" in self.path:
                stream += "data: [DONE]\n\n"
            self.respond(stream, "text/event-stream")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix=f"tinfoil-{name}-") as directory:
            home = Path(directory)
            base = f"http://127.0.0.1:{server.server_port}"
            env = {
                "HOME": directory,
                "PATH": os.environ["PATH"],
                "TERM": "dumb",
                "NO_COLOR": "1",
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_DATA_HOME": str(home / ".local/share"),
                "XDG_CACHE_HOME": str(home / ".cache"),
            }
            runpy.run_path(str(ROOT / "rootfs/usr/local/libexec/seed-agent-config"))[
                "seed"
            ](home, TEMPLATES)

            def local_config(source, target):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    source.read_text().replace("https://inference.tinfoil.sh", base)
                )
                return str(target)

            prompt = "Reply with " + REPLY + ". Do not use tools."
            if name == "claude":
                config = local_config(TEMPLATES / "claude.json", home / "claude.json")
                # Check that opting in clears a pre-existing Anthropic key.
                env["ANTHROPIC_API_KEY"] = "unrelated-user-key"
                args = ["--settings", config, "-p", prompt, "--max-turns", "1"]
            elif name == "codex":
                local_config(
                    TEMPLATES / "codex.toml", home / ".codex/tinfoil.config.toml"
                )
                args = [
                    "exec",
                    "--strict-config",
                    "--profile",
                    "tinfoil",
                    "--skip-git-repo-check",
                    prompt,
                ]
            elif name == "opencode":
                env["OPENCODE_CONFIG"] = local_config(
                    ROOT / "rootfs/etc/opencode/opencode.json", home / "opencode.json"
                )
                # Keep offline smoke tests independent of provider/plugin downloads.
                env.update(
                    OPENCODE_DISABLE_MODELS_FETCH="true",
                    OPENCODE_DISABLE_DEFAULT_PLUGINS="true",
                    OPENCODE_DISABLE_AUTOUPDATE="true",
                )
                args = ["run", "--model", "tinfoil/kimi-k3", prompt]
            elif name == "crush":
                local_config(
                    ROOT / "rootfs/etc/crush/crush.json",
                    home / ".config/crush/crush.json",
                )
                env.update(
                    CRUSH_DISABLE_PROVIDER_AUTO_UPDATE="1", CRUSH_DISABLE_METRICS="1"
                )
                args = [
                    "run",
                    "--model",
                    "tinfoil/kimi-k3",
                    "--small-model",
                    "tinfoil/kimi-k3",
                    prompt,
                ]
            elif name == "qwen":
                env["QWEN_CODE_SYSTEM_DEFAULTS_PATH"] = local_config(
                    ROOT / "rootfs/etc/qwen-code/system-defaults.json",
                    home / "qwen-defaults.json",
                )
                args = ["--auth-type", "openai", "--model", "kimi-k3", "-p", prompt]
            elif name == "pi":
                local_config(TEMPLATES / "pi.json", home / ".pi/agent/models.json")
                args = ["--provider", "tinfoil", "--model", "kimi-k3", "-p", prompt]
            elif name == "goose":
                local_config(
                    TEMPLATES / "goose.json",
                    home / ".config/goose/custom_providers/tinfoil.json",
                )
                args = [
                    "run",
                    "--no-profile",
                    "--provider",
                    "tinfoil",
                    "--model",
                    "kimi-k3",
                    "--text",
                    prompt,
                ]
            elif name == "copilot":
                for line in (TEMPLATES / "copilot.env").read_text().splitlines():
                    if line.startswith("export "):
                        key, value = line[7:].split("=", 1)
                        env[key] = value.replace("https://inference.tinfoil.sh", base)
                args = ["-p", prompt]
            else:
                local_config(TEMPLATES / "droid.json", home / ".factory/settings.json")
                args = [
                    "exec",
                    "--model",
                    "custom:Kimi-K3-(Tinfoil-through-Monitor)-0",
                    prompt,
                ]
            command = [str(binary), *args]
            if system_configs and name in ("opencode", "crush", "qwen"):
                # Exercise the actual /etc lookup without changing the host.
                files = {
                    "opencode": (home / "opencode.json", "/etc/opencode/opencode.json"),
                    "crush": (
                        home / ".config/crush/crush.json",
                        "/etc/crush/crush.json",
                    ),
                    "qwen": (
                        home / "qwen-defaults.json",
                        "/etc/qwen-code/system-defaults.json",
                    ),
                }
                source, destination = files[name]
                if name == "crush":
                    source = source.rename(home / "crush-system.json")
                env.pop("OPENCODE_CONFIG", None)
                env.pop("QWEN_CODE_SYSTEM_DEFAULTS_PATH", None)
                mounts = []
                for path in (
                    "/etc/passwd",
                    "/etc/group",
                    "/etc/hosts",
                    "/etc/resolv.conf",
                    "/etc/nsswitch.conf",
                    "/etc/ssl",
                ):
                    mounts.extend(["--ro-bind", path, path])
                command = [
                    "bwrap",
                    "--ro-bind",
                    "/",
                    "/",
                    "--dev-bind",
                    "/dev",
                    "/dev",
                    "--proc",
                    "/proc",
                    "--bind",
                    directory,
                    directory,
                    "--tmpfs",
                    "/etc",
                    *mounts,
                    "--ro-bind",
                    str(source),
                    destination,
                    "--",
                    *command,
                ]
            try:
                result = subprocess.run(
                    command,
                    cwd=home,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                )
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired as error:
                return (
                    name,
                    False,
                    "timed out; requests="
                    + str([(p, b.get("model")) for p, _, b in requests])
                    + "\n"
                    + str(error.stderr)[-1500:],
                )
            inference = [r for r in requests if "count_tokens" not in r[0]]
            if not inference:
                return (
                    name,
                    False,
                    f"no inference request (exit {result.returncode}): {output[-1800:]}",
                )
            for path, headers, body in requests:
                headers = {k.lower(): v for k, v in headers.items()}
                assert headers.get("authorization") == "Bearer " + TOKEN, (
                    name,
                    headers,
                )
                assert all(
                    TOKEN not in v for k, v in headers.items() if k != "authorization"
                ), (name, headers)
                assert "x-api-key" not in headers, (name, headers)
                assert body.get("model") == "kimi-k3", (name, body.get("model"))
                assert path.split("?")[0] in (
                    "/v1/chat/completions",
                    "/v1/responses",
                    "/v1/messages",
                    "/v1/messages/count_tokens",
                ), (name, path)
            success = result.returncode == 0 and REPLY in output
            return (
                name,
                success,
                f"{len(inference)} request(s), bearer/model/path verified, exit {result.returncode}"
                + ("" if success else "\n" + output[-1800:]),
            )
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bin-dir", type=Path, default=Path("/nix/var/nix/profiles/default/bin")
    )
    parser.add_argument("agents", nargs="*", default=AGENTS)
    parser.add_argument(
        "--system-configs",
        action="store_true",
        help="Use bwrap to exercise native /etc paths for OpenCode, Crush and Qwen",
    )
    args = parser.parse_args()
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(
            pool.map(
                lambda name: smoke(name, args.bin_dir / name, args.system_configs),
                args.agents,
            )
        )
    for name, passed, detail in results:
        print(f"{'PASS' if passed else 'FAIL'} {name}: {detail}")
    raise SystemExit(0 if all(passed for _, passed, _ in results) else 1)
