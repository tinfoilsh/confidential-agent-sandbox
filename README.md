# Confidential Agent Sandbox

An Ubuntu VM with Docker, encrypted storage, and network access through Monitor.

Create a Monitor and sandbox in the dashboard, then connect:

```sh
tinfoil attest-ssh work --install
ssh work
```

Rerun `attest-ssh` after either VM reboots. Back up the CLI's encryption credentials.

For direct networking, select **Run without Monitor (NO_MONITOR=1)** when creating
the sandbox in the dashboard. This sets the measured `NO_MONITOR` environment
variable to `1` and omits the host network policy. The sandbox keeps its normal
DNS and disables both Monitor tunnels. The same commands verify attestation and
unlock the workspace through the published SSH port; the CLI warns that traffic
is not tunneled through Monitor. Any other value keeps Monitor enabled.
Use a release containing this option and the matching CLI; older templates do
not declare `NO_MONITOR` and cannot accept it.

SSH logins show a short Tinfoil welcome in place of Ubuntu's default MOTD.
The release build stamps its version into the banner; local builds show `dev`
unless built with `--build-arg SANDBOX_VERSION=...`. The connectivity hint uses
`<name>` because the dashboard name is not passed into the sandbox.

Shells keep Ubuntu's standard prompt and key bindings. The toolchain's Starship,
Atuin, zoxide, and Carapace hooks are not enabled automatically.

Coding agents start with their normal provider selection and authentication.
Tinfoil is an optional provider or launch setting; there are no agent wrappers
or `monitor agent` command.

Add a **Tinfoil** account in Monitor, leave its connection named **`tinfoil`**,
save the real API key there, and grant the sandbox access. Grant **Inference →
Generate responses**, **Count input tokens** for Claude, and **List models** for
clients that discover models. Check the connection name and readiness with
`monitor connections`.

The following inventory was checked against `nix-closure` commit `aa839b2`,
with nixpkgs `42f17a57f4f6e33b3de3dca0a2a5ea5233169d02`. The sandbox template pins
modelpack `5vh6n2f157y8kwsdjprdnxqg41m5im0m`; an already-running VM keeps its
mounted pack until updated. The older `kzqj4szd` pack also contained Hermes and
lacked seven of these agents. Hermes is no longer in the toolchain source.

| Agent | Audited version | Choose Tinfoil |
| --- | --- | --- |
| OpenCode (`opencode`) | 1.18.29 | `/models` → Tinfoil / Kimi K3, or `opencode --model tinfoil/kimi-k3` |
| Claude Code (`claude`) | 2.1.260 | `claude --settings /usr/local/share/tinfoil/claude.json` |
| Codex (`codex`) | 0.153.4 | `codex --profile tinfoil` |
| Crush (`crush`) | 0.91.2 | Tinfoil in the model picker; `crush models` lists it |
| Qwen Code (`qwen`) | 0.16.0 | `/model` → Tinfoil / Kimi K3 under OpenAI-compatible models; or `qwen --auth-type openai --model kimi-k3` |
| pi (`pi`) | 0.85.1 | `/model` → Tinfoil, or `pi --provider tinfoil --model kimi-k3` |
| Goose (`goose`) | 1.47.0 | Select Tinfoil in `goose configure`, or `goose session --provider tinfoil --model kimi-k3` |
| Droid (`droid`) | 0.213.0 | `/model` → Custom models → Kimi K3 (Tinfoil through Monitor); requires the packaging fix below |
| GitHub Copilot (`copilot`) | 1.0.61 | `(. /usr/local/share/tinfoil/copilot.env; copilot)` |
| Amp (`amp`) | 0.0.1788367255-g70055c | No supported local provider setting for this Monitor path |
| Cursor CLI (`cursor-agent`) | 2026.08.31-4057e58 | No supported OpenAI-compatible provider setting in this version |
| Antigravity (`agy`) | 1.1.24 | No supported OpenAI-compatible provider setting in this version |

Claude selects its endpoint at launch. The opt-in settings use
`ANTHROPIC_AUTH_TOKEN` and clear `ANTHROPIC_API_KEY`/`apiKeyHelper`, so the
placeholder is only sent in the Authorization header. Codex uses a separate
`~/.codex/tinfoil.config.toml` file, as required by the pinned version; it does
not use the old `[profiles.tinfoil]` format. Copilot 1.0.61 supports the
`COPILOT_PROVIDER_*` environment variables but does not read the provider
registry described in newer Copilot documentation. The subshell keeps those
variables local to that launch.

OpenCode, Crush and Qwen load provider declarations from
`/etc/opencode/opencode.json`, `/etc/crush/crush.json`, and
`/etc/qwen-code/system-defaults.json`. None sets a default model or restricts
the provider list. Qwen user/project `modelProviders` replaces the system
list; users with their own list can copy the Tinfoil entry into it. OpenCode's
system provider entry is managed configuration; users can hide it with
`disabled_providers`, while changing its endpoint/token requires editing the
system file.

After home is mounted, `seed-agent-config` adds pi's provider to
`~/.pi/agent/models.json`, Droid's custom model to `~/.factory/settings.json`,
Goose's provider to `~/.config/goose/custom_providers/tinfoil.json`, and the
Codex profile. It runs for `sandbox` and `root`. Existing entries and model
selections are preserved. These files contain public Monitor placeholders,
never the real key. Goose supplies its placeholder as a fixed Authorization
header, so it does not prompt for a key. Programs still apply their normal
first-run/last-used model selection behavior.

On upgrades from `v0.1.17`, only byte-for-byte matches of that release's four
seeded default files are removed. Modified files, including login state,
are preserved. If an edited old configuration still forces Tinfoil, remove
its default model/endpoint/provider restriction manually; when keeping an
old Tinfoil entry, replace its launcher-only credential reference with the
placeholder from the new configuration. Custom `CODEX_HOME`, `QWEN_HOME`,
`PI_CODING_AGENT_DIR`, and other config directory overrides require copying
the corresponding entry to that location.

Monitor still owns the cryptography. The existing system network service
preserves DNS hostnames through its TUN/SOCKS/SSH connection. Monitor routes
`inference.tinfoil.sh` to its Tinfoil connector, terminates client TLS with its
CA, checks policy, substitutes the real credential, verifies the enclave,
and establishes the attested upstream TLS connection. The sandbox's CA
settings remain in `/etc/environment`. Chat Completions clients use
`/v1/chat/completions`, Codex uses `/v1/responses`, and Claude uses the existing
Messages translation in the connector. No connector or attestation code is
changed here.

Static configuration assumes one accessible connector claims
`inference.tinfoil.sh`, named `tinfoil`. Renaming it requires updating the
placeholder in the relevant config files. Multiple equally specific claims
are rejected by Monitor; grant this sandbox access to one such connection.
`TINFOIL_CONNECTION` is no longer a launcher setting. Other providers and
any client catalog, plugin, update, or login requests still need their own
Monitor network permissions.

[Amp model routing](https://ampcode.com/docs/customize/model-routing) configures
account/workspace connections and requires an endpoint reachable from Amp.
It cannot consume the sandbox-local Monitor placeholder. [Cursor CLI
configuration](https://cursor.com/docs/cli/reference/configuration) and
[Antigravity CLI](https://antigravity.google/docs/cli/overview) expose their
own model selection, without a local OpenAI-compatible endpoint option in
the audited versions. These three agents remain available with their vendor
backends; no local Tinfoil configuration is installed for them.

Provider format references: [OpenCode](https://opencode.ai/docs/config/),
[Claude Code](https://code.claude.com/docs/en/llm-gateway),
[Codex](https://developers.openai.com/codex/config-advanced),
[Crush](https://github.com/charmbracelet/crush/blob/v0.91.2/README.md#custom-providers),
[Qwen](https://github.com/QwenLM/qwen-code/blob/v0.16.0/packages/cli/src/config/settings.ts),
[pi](https://github.com/earendil-works/pi/blob/v0.85.1/packages/coding-agent/docs/models.md),
[Goose](https://github.com/aaif-goose/goose/blob/v1.47.0/documentation/docs/getting-started/providers.md#configure-custom-provider),
[Droid](https://docs.factory.com/model-independence/byok), and the pinned
`copilot help providers` output.

Validation and rollout:

- `python3 -m unittest discover -s tests -v` covers boot configuration,
  preservation of user settings, idempotency, and the actual `v0.1.17` fixtures.
- `python3 tests/smoke_agents.py --bin-dir /nix/var/nix/profiles/default/bin`
  runs the nine supported clients with disposable homes and a local mock
  inference server. It checks a complete text response, the model, endpoint,
  bearer header, and absence of an API-key header. `--system-configs` uses
  Bubblewrap to check the actual `/etc` lookup for OpenCode, Crush and Qwen.
  The mock test disables catalog/plugin downloads for OpenCode and catalog
  updates for Crush to isolate provider behavior.
- The old Nix Droid derivation stripped Bun's embedded application, leaving
  `droid --version` reporting Bun `1.3.14`. The companion `nix-closure` change
  sets `dontStrip = true` and adds an install-time version check. Its rebuilt
  binary reports `0.213.0` and passes the mock inference test.
- Roll out that package fix by rebuilding/publishing the Nix pack and updating
  both `models[].repo` and `models[].mwp` in `tinfoil-config.yml`, then building
  and releasing the sandbox image. A source-only package fix does not repair
  the pack already pinned here.
- Live CVM boot, vendor sign-in, first-run downloads under real Monitor policy,
  and inference through a deployed Monitor/enclave have not been exercised by
  these mock tests. Verify them after rollout, including an existing encrypted
  home. No live credentials are needed for the local tests.
