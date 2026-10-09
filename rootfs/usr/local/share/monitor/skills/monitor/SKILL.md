---
name: monitor
description: Discover accounts available through Monitor, run HTTP clients with its credentials and approval policy, and connect MCP tools.
---

# Monitor

Run `monitor connections --json` to discover accounts granted to this sandbox,
their connection names, and their current status.

HTTP and HTTPS traffic already goes through Monitor system-wide. Its CA is in the
system trust store. Direct internet egress is closed; the owner must keep the
Monitor reverse forward connected.

Use the wrapper when you need credential placeholders or account selection:

```sh
monitor run -- curl -fsS https://example.com
monitor shell
```

Use destinations allowed by the discovered accounts. Select an account with
`monitor run --connection NAME -- COMMAND`. The wrapper sets proxy and certificate
settings and supplies credential placeholders. Monitor substitutes real credentials
upstream. Transparent routing also covers tools that ignore proxy settings.

Shared credential names have separate variables such as
`MONITOR_CREDENTIAL_ANTHROPIC_TOKEN`. When a tool expects a different variable,
map the placeholder to that variable inside the wrapped command. Never ask for
or copy the owner's key or provider credentials into the sandbox.

For MCP accounts, keep this running and configure your MCP client for the URL it reports:

```sh
monitor mcp serve --listen 127.0.0.1:8400
```

An HTTP account alone does not expose MCP tools. The owner must grant the MCP
account and review its tools. Requests that need approval wait for the owner;
if access is missing, ask the owner to grant it. After a timeout, check whether
an operation completed before retrying a write.

`monitor --help` lists the SSH host, configuration, and profile options.
