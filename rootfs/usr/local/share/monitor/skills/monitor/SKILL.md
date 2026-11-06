---
name: monitor
description: Discover and use connections granted to this sandbox, inspect its own Monitor policy, and propose connection or access changes for owner review without handling credentials.
---

# Monitor in a sandbox

Monitor is this sandbox's policy and credential boundary for external services.
Use the installed `monitor` CLI unless directly integrating with the internal
agent API.

## Rules

- Never ask for or use the Monitor owner key.
- Never ask for provider credentials. The owner configures them separately.
- Inspect the catalog warning before proposing a Generic connection.
- Prefer a named service connection over Generic Web, SSH, network, API, or MCP.
- A proposal is only a request. Do not assume access changed until discovery or
  policy shows it.
- Propose only connections and access needed by this sandbox. Do not request
  changes for another sandbox.
- Connection approval does not approve MCP tools; the owner reviews tool
  definitions separately.

## Discover

See the safe connection catalog:

```sh
monitor catalog --json
```

Catalog entries describe setup fields, defaults, connection templates, and
shared `warning` copy. `vocabulary` describes the effects referenced by catalog
actions. The final `generic` group contains broad fallback types.

See connections this sandbox can currently use:

```sh
monitor connections --json
```

Discovery includes connection names, protocols, readiness, effective access,
allowed hosts, safe credential placeholders, and credential states such as
`unset`, `static`, `oauth`, or `oauth-required`. It never includes credential
values or verified credential account identifiers.

See this sandbox's own policy projection:

```sh
monitor policy show
monitor policy show --json
```

The sandbox view contains this identity's access and saved rules plus semantics
for connections it can reach. It does not reveal other sandboxes, owner-only policy,
or credentials.

## Request a connection or access change

Prefer structured changes for automation:

```sh
monitor policy propose --changes changes.json \
  --reason "Grant this sandbox GitHub access for issue triage"
```

Example `changes.json`:

```json
[
  {
    "path": ["identities", "my-sandbox", "connections", "github", "level"],
    "value": "ask"
  }
]
```

Use the exact sandbox identity shown by `monitor policy show`. A deletion uses
`"delete": true` and omits `value`. TOML fragments are also accepted:

```sh
monitor policy propose change.toml \
  --reason "Grant this sandbox GitHub access for issue triage"
```

Proposals may contain shared connection setup or access for this sandbox only.
They cannot change default access, credentials, MCP tool pins, identity keys or
routes, global policies, data, global effect defaults, or other owner
configuration. Monitor validates the candidate and removes semantic no-ops before
publishing it.

A batch is split into one proposal per connection. The owner reviews each
connection independently. Poll the ID from a submitted receipt with:

```sh
monitor policy status PROPOSAL_ID
```

Status is limited to this sandbox's own proposals and reports `pending`,
`approved`, `denied`, or `outdated`. It is process-local like the
pending proposal itself. If a relevant setting changes first, Monitor records the
proposal as Outdated; submit a new proposal if it is still needed.

## Use connections

HTTP and HTTPS traffic already goes through Monitor system-wide, and its CA is
in the system trust store. Direct internet egress is closed; the owner must keep
the Monitor reverse forward connected. Transparent routing also covers tools
that ignore proxy settings.

Use the wrapper when you need credential placeholders or a specific connection:

```sh
monitor run --connection CONNECTION -- curl -fsS https://example.com
monitor run -- your-command
monitor shell
```

The wrapper configures proxy and certificate settings and exposes safe credential
placeholders. Monitor substitutes real credentials upstream. Never replace a
placeholder with a real credential.

For MCP connections:

```sh
monitor mcp serve --listen 127.0.0.1:8400
```

Keep it running and configure the MCP client with the reported local URL. Only
ready connections granted to this sandbox are served.

A request that needs approval may wait and time out. After an uncertain write
timeout, inspect the destination or Activity before retrying.

## Direct internal API

Inside the managed sandbox, the identity-authenticated API is available at
`agent.monitor`:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/catalog` | Safe connection catalog and warnings |
| `GET` | `/connections` | Connections granted to this sandbox |
| `GET` | `/policy` | This sandbox's credential-free policy view |
| `GET` | `/policy/proposals/{id}` | Poll this sandbox's submitted proposal |
| `POST` | `/policy/proposals` | Submit owner-reviewed connection changes |

```sh
curl -fsS http://agent.monitor/catalog
curl -fsS http://agent.monitor/connections
curl -fsS http://agent.monitor/policy
curl -fsS -X POST http://agent.monitor/policy/proposals \
  -H 'Content-Type: application/json' \
  --data-binary @proposal.json
```

A structured proposal body has `reason` and a non-empty `changes` array.
Responses contain `{id, state, connection}` receipts, not owner-only
configuration or diffs. Resubmitting identical changes returns the pending receipt.
