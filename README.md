# Confidential Agent Sandbox

An Ubuntu 24.04 workspace inside a confidential VM. It has systemd, its own
Docker daemon, and an encrypted disk that keeps your files between sessions.

## Use one

```sh
tinfoil monitor create personal
tinfoil sandbox create work --monitor personal
ssh work
```

The CLI generates independent owner and disk keys. It binds
`SANDBOX_OWNER_PUBLIC_KEY` in the measured config; OpenSSH uses that exact key
for both disk unlock and login. Use the same computer for later commands;
credentials stay in `~/.tinfoil/sandboxes/<name>`. The dashboard provides the CLI
command.

For a stopped sandbox or a boot started from the dashboard, run
`tinfoil sandbox start work` to unlock it and install the attested SSH profile.
Connect with `ssh work`; use `tinfoil sandbox enroll work` to retry unlock.

The sandbox boots with `MONITOR_ROUTE`, a JSON object containing the Monitor's
public domain, sandbox-facing IPv4 address, SSH port and attested host key. It
starts reverse SSH before disk unlock. The device needs Monitor route access;
the sandbox's publishing key needs no account grant.

Virtual port 443 reaches the sandbox's loopback HTTPS server on port 8443.
Its TLS certificate uses the attested boot key. It proxies attestation requests
to `/tinfoil/attestation.sock`. Public HTTP serves health only.

After verifying fresh attestation, the CLI connects to virtual port 22 with the
owner key and pins the sandbox's attested SSH host key. Before disk unlock,
OpenSSH permits only `workspace-enroll --unlock`, with no shell, PTY or
forwarding. The helper sends the disk key and Monitor agent identity through a
private Unix socket to the root unlock service. That service opens the volume
and saves the agent identity. It accepts no login key or route.
After the disk is mounted, normal SSH starts with the same owner key. Identical
unlock retries are safe, including after the daemon handoff. There is no custom
owner challenge or signed HTTP enrollment.

The controlplane restricts egress to the assigned Monitor; the measured boot
address must match that allowed endpoint.

Home directories, `/workspace`, Docker state, and installed packages stay on the
disk. Packages are kept per image build, so an updated image starts without them.
Everything else is reset when the sandbox is recreated.

After unlock and mounting, `monitor-configure.service` writes this boot's
Monitor configuration under `/run/monitor`. The network and reverse SSH services
wait for it. Routing always comes from measured `MONITOR_ROUTE`; only the agent
identity comes from the disk. Systemd takes over the reverse SSH connection and
restarts it after disconnects. Its SSH username is the measured owner public
key, allowing Monitor to locate the attestation route before the device knows
the boot key. No runtime `DOMAIN` is needed. Environment entries are literal
mappings, including empty template defaults; provisioning must fill them before
publishing the measured config.
