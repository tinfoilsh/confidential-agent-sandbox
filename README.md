# Confidential Agent Sandbox

An Ubuntu VM with Docker, encrypted storage, and network access through Monitor.

Create a Monitor and sandbox in the dashboard, then connect:

```sh
tinfoil attest-ssh work --install
ssh work
```

Rerun `attest-ssh` after either VM reboots. Back up the CLI's encryption credentials.


`opencode`, `claude`, and `codex` are installed and default to `kimi-k3` through
Monitor. Add a **Tinfoil** account in Monitor, save the API key there, and grant
the sandbox account access plus **Inference → Generate responses**. Then run any
of the three commands normally. No provider login or API key in the sandbox is
needed. The launchers discover an accessible Tinfoil connection, use its
placeholder credential, and establish the existing Monitor SSH/proxy session.
Attestation and upstream TLS pinning happen in Monitor, including when it runs
connectors in isolated workers.

If several Tinfoil accounts are accessible, set
`TINFOIL_CONNECTION=<connection-name>`. `monitor connections` lists them.
Help and version commands work before Monitor is paired. Client configuration is
seeded for `sandbox` and `root` after the encrypted home is mounted; existing
files are preserved. Defaults live in `~/.claude/settings.json`,
`~/.codex/config.toml`, and `~/.config/opencode/opencode.json` and can be edited.
OpenCode uses Chat Completions, Codex uses Responses, and Monitor translates
Claude's Messages requests (including streaming and local tool use).

Claude and Codex come from the pinned Nix toolchain in `tinfoil-config.yml`.
OpenCode is version- and checksum-pinned in the Dockerfile. All three binaries
are present before the first command; default OpenCode provider discovery and
auth plugin downloads are disabled by its launcher.
