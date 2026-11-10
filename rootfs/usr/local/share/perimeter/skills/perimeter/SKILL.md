---
name: perimeter
description: Discover and use connections granted to this sandbox, inspect its own Perimeter policy, and propose connection or access changes for owner review without handling credentials.
---

# Perimeter in a sandbox

The Perimeter is this sandbox's policy and credential boundary for external services.
Use the installed `perimeter` CLI unless directly integrating with the internal
agent API.

## Rules

- Never ask for or use the Perimeter owner key.
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
perimeter catalog --json
```

Catalog entries describe setup fields, defaults, connection templates, and
shared `warning` copy. `vocabulary` describes the effects referenced by catalog
actions. The final `generic` group contains broad fallback types.

See connections this sandbox can currently use:

```sh
perimeter connections --json
```

Discovery includes connection names, protocols, readiness, effective access,
allowed hosts, safe credential placeholders, and credential states such as
`unset`, `static`, `oauth`, or `oauth-required`. It never includes credential
values or verified credential account identifiers.

See this sandbox's own policy projection:

```sh
perimeter policy show
perimeter policy show --json
```

The sandbox view contains this identity's access and saved rules plus semantics
for connections it can reach. It does not reveal other sandboxes, owner-only policy,
or credentials.

## Request a connection or access change

Prefer structured changes for automation:

```sh
perimeter policy propose --changes changes.json \
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

Use the exact sandbox identity shown by `perimeter policy show`. A deletion uses
`"delete": true` and omits `value`. TOML fragments are also accepted:

```sh
perimeter policy propose change.toml \
  --reason "Grant this sandbox GitHub access for issue triage"
```

Proposals may contain shared connection setup or access for this sandbox only.
They cannot change default access, credentials, MCP tool pins, identity keys or
routes, global policies, data, global effect defaults, or other owner
configuration. The Perimeter validates the candidate and removes semantic no-ops before
publishing it.

A batch is split into one proposal per connection. The owner reviews each
connection independently. Poll the ID from a submitted receipt with:

```sh
perimeter policy status PROPOSAL_ID
```

Status is limited to this sandbox's own proposals and reports `pending`,
`approved`, `denied`, or `outdated`. It is process-local like the
pending proposal itself. If a relevant setting changes first, the Perimeter records the
proposal as Outdated; submit a new proposal if it is still needed.

## Use connections

HTTP and HTTPS traffic already goes through the Perimeter system-wide, and its CA is
in the system trust store. Direct internet egress is closed; the owner must keep
the Perimeter reverse forward connected. Transparent routing also covers tools
that ignore proxy settings.

Use the wrapper when you need credential placeholders or a specific connection:

```sh
perimeter run --connection CONNECTION -- curl -fsS https://example.com
perimeter run -- your-command
perimeter shell
```

The wrapper configures proxy and certificate settings and exposes safe credential
placeholders. The Perimeter substitutes real credentials upstream. Never replace a
placeholder with a real credential.

For MCP connections:

```sh
perimeter mcp serve --listen 127.0.0.1:8400
```

Keep it running and configure the MCP client with the reported local URL. Only
ready connections granted to this sandbox are served.

A request that needs approval may wait and time out. After an uncertain write
timeout, inspect the destination or Activity before retrying.

## Direct internal API

Inside the managed sandbox, the identity-authenticated API is available at
`agent.perimeter`:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/catalog` | Safe connection catalog and warnings |
| `GET` | `/connections` | Connections granted to this sandbox |
| `GET` | `/policy` | This sandbox's credential-free policy view |
| `GET` | `/policy/proposals/{id}` | Poll this sandbox's submitted proposal |
| `POST` | `/policy/proposals` | Submit owner-reviewed connection changes |

```sh
curl -fsS http://agent.perimeter/catalog
curl -fsS http://agent.perimeter/connections
curl -fsS http://agent.perimeter/policy
curl -fsS -X POST http://agent.perimeter/policy/proposals \
  -H 'Content-Type: application/json' \
  --data-binary @proposal.json
```

A structured proposal body has `reason` and a non-empty `changes` array.
Responses contain `{id, state, connection}` receipts, not owner-only
configuration or diffs. Resubmitting identical changes returns the pending receipt.
