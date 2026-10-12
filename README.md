# Confidential Agent Sandbox

An Ubuntu 24.04 workspace inside a confidential VM, with systemd, Docker and an
encrypted disk that keeps your files between sessions.

Create a Monitor and sandbox in the dashboard using compatible release tags and
your Ed25519 SSH public key. Then run:

```sh
tinfoil attest-ssh work --install
ssh work
```

Rerun `attest-ssh` after either VM reboots. Use `--identity PATH` or ssh-agent for
your existing owner key. Back up the encryption credentials saved by the CLI;
your SSH key alone cannot recover the disk.

The bootstrap reverse tunnel publishes only SSH and attestation using the sandbox
boot key. It treats Monitor as an untrusted relay. Owner SSH verifies this boot
before releasing disk or agent keys and installs Monitor's current attested key
for application traffic. Only bootstrap skips Monitor host-key checks; application
SSH and native ProxyJump remain strictly pinned.

`SANDBOX_OWNER_PUBLIC_KEY`, `SANDBOX_INSTANCE_ID` and `MONITOR_BINDING` are measured.
The binding contains Monitor's container UUID and owner public key. The optional
runtime `MONITOR_ENDPOINT` is an IPv4:port locator. Omit it from create variables;
the dashboard sets it on deploy after resolving the allowed network endpoint.
A boot without it keeps owner SSH and attestation healthy while waiting.

If Monitor's endpoint or host grant changes, restart the sandbox explicitly, then
rerun `attest-ssh`. Deleting the sandbox retains its billable workspace volume.
