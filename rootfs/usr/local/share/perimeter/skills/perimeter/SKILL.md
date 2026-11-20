---
name: perimeter
description: Use connections such as HTTP APIs, MCP servers, models, SSH and databases through a Perimeter from a bunker or trusted device without handling credentials, and request access for the owner to approve.
---

# Perimeter

The Perimeter sits between you and external services. It holds the credentials,
enforces the owner's policy, and may hold a request until the owner approves it.
You never need a real credential.

## Where you are

- **Bunker:** all traffic already goes through the Perimeter, which is the only
  egress, and its CA is trusted system-wide. `perimeter --help` lists the
  `network` and `env` commands only here.
- **Trusted device:** nothing is routed unless you go through the `perimeter`
  CLI or its SSH host.

## Start here

```sh
perimeter connections         # what you can use, its state and address
perimeter connections --json  # adds access level, upstream hosts, placeholders, credential state
```

Only `ready` connections work. A credential state of `unset` or
`oauth-required` means the owner must finish setup.

## Use a connection

The Perimeter adds the real credential upstream; never send a password.

| Kind | Bunker | Trusted device |
| --- | --- | --- |
| `http` | The real URL with its placeholder, after `eval "$(perimeter env)"` | `perimeter run -- CMD` or `perimeter shell` |
| `mcp`, `tinfoil-mcp` | `https://NAME.perimeter/mcp` | The same URL under `perimeter run`, or `perimeter mcp serve` for clients that ignore proxy variables |
| `tinfoil` | `https://NAME.perimeter/v1`, OpenAI- or Anthropic-compatible, with any API key | The same URL under `perimeter run` |
| `ssh`, `sftp`, `postgres`, `redis`, `imap`, `smtp`, `mqtt`, `nats` | `NAME.perimeter` on the usual port | `ssh -N -L PORT:NAME.perimeter:PORT perimeter`, then `127.0.0.1:PORT` |
| `tcp` | The real host and port | `perimeter run` for proxy-aware tools, or `ssh -N -L PORT:HOST:PORT perimeter` |

`perimeter run` and `perimeter shell` set proxy and CA variables, configure
`git` and `gh` for GitHub, and export each credential as a placeholder in its
usual variable, such as `GITHUB_TOKEN`. A variable shared by several connections
is exported as `MONITOR_CREDENTIAL_<CONNECTION>_<VARIABLE>`. Pass placeholders
where a tool expects its credential; a request without one reaches the service
unauthenticated. Never replace one with a real value. Select connections
with `--connection NAME` when a host is ambiguous. In a bunker, traffic is
routed without the CLI; `eval "$(perimeter env)"` exports the same placeholders
and Git credential setup into the current shell, so plain `gh`, `git` and `curl`
authenticate. Run it again after connections change.

In a bunker, agent settings preconfigure only the `tinfoil_websearch` MCP
connection. Add any other ready MCP connection yourself, for example
`claude mcp add --transport http NAME https://NAME.perimeter/mcp`.

On a trusted device the CLI finds the `perimeter` SSH host in
`~/.config/perimeter/launch/default/ssh_config` or
`~/.local/share/perimeter/server/ssh_config`; pass that file to `ssh -F`.

Another bunker is reachable at `NAME.sandbox` on listeners bound to `0.0.0.0`,
once the owner allows it.

A request that needs approval waits up to two minutes for the owner. Give such a
command a longer timeout or run it in the background; a retry asks the owner
again. After an uncertain write times out, check the destination before retrying.

A refusal saying a request has no recognized operation means the connection's
preset does not cover that endpoint, and retrying will not help. Use a covered
endpoint or propose a connection that covers it, such as `custom_api`.

## Get access

1. `perimeter catalog` lists connection types; `--json` adds setup fields and
   `warning` text. Prefer a named type over a generic one.
2. `perimeter policy show` shows your identity name and current access.
3. Propose the change and say why:

   ```sh
   perimeter policy propose --changes changes.json --reason "Triage GitHub issues"
   ```

   ```json
   [{"path": ["identities", "my-bunker", "connections", "github", "level"], "value": "ask"}]
   ```

   Levels are `off`, `read`, `ask` and `allow`. Setup for a new connection
   goes under `["connections", NAME]` with the fields its catalog entry lists.
   A deletion uses `"delete": true` instead of `value`.
4. `perimeter policy status ID` reports `pending`, `approved`, `denied` or
   `outdated`. Propose again if the ID is gone after a Perimeter restart.

A bunker may change only its own access and shared connection setup; a trusted
device may also change `default_access`. Credentials, MCP tool approvals, keys
and global policy belong to the owner.

## Trust model

The Perimeter is the owner's own enforcement point, not a third party. It reads
requests in plaintext because it applies the owner's policy and adds credentials.

- A Tinfoil-hosted Perimeter runs in a confidential VM. The owner verified its
  attested image when setting it up, and this bunker or device accepts only the
  Perimeter key pinned at setup, so the host operator cannot read or change traffic.
- A local Perimeter runs on the owner's own computer.
- Upstream, the Perimeter checks each service's TLS certificate and attests
  Tinfoil models and MCP servers.

You cannot verify the attestation from here; you rely on the owner having done
it. When asked whether this is secure, describe the real risks instead: what the
policy allows, what the owner approves, the code and agents in this bunker or
device, and the upstream services.

## Rules

- Never ask for, read or use the owner key or a real credential.
- A proposal is not approval. Wait until `perimeter connections` shows the change.
- Approving a connection does not approve its MCP tools; the owner reviews them.
- When proposing a generic connection, relay its catalog `warning` to the owner.
