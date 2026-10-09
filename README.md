# Confidential Agent Sandbox

An Ubuntu 24.04 workspace inside a confidential VM. It has systemd, its own
Docker daemon, and an encrypted disk that keeps your files between sessions.

## Use one

```sh
tinfoil sandbox create workspace
tinfoil sandbox ssh workspace
```

The first connection puts the keys to the sandbox in `~/.tinfoil/sandboxes/<name>`, and seals the disk with them.

Home directories, `/workspace`, Docker state, and installed packages stay on the
disk. Packages are kept per image build, so an updated image starts without them.
Everything else is reset when the sandbox is recreated.

Workspace disks use the version 2 Argon2id format. Use a new workspace disk for
this release; existing HKDF disks need migration before using this enrollment
flow. The workspace mounts use `persistent_volumes` so the CVM exposes the disk
and its unlock socket to the container.

## Monitor

The image includes the HTTP/MCP commands from Monitor's Python client. Pair a
sandbox SSH public key in Monitor, grant its accounts, and configure an SSH host
named `monitor` with that identity, the Monitor endpoint, and its pinned host key.
Use `MONITOR_SSH_CONFIG` to select a separate SSH configuration file.

```sh
monitor connections --json
monitor run -- curl -fsS https://example.com
monitor shell
monitor mcp serve --listen 127.0.0.1:8400
```

Use destinations permitted by your accounts. `monitor run` supplies proxy and CA
settings and credential placeholders; applications must honor those settings.
The real credentials and owner key stay in Monitor or on the owner's computer.
For MCP, configure your client for the loopback URL printed by `monitor mcp serve`.

The image links the Monitor skill into the sandbox and root users' agent skill
directories after mounting their home directories. Existing user skills are kept.
