# Confidential Agent Sandbox

An Ubuntu 24.04 workspace inside a confidential VM. It has systemd, its own
Docker daemon, and an encrypted disk that keeps your files between sessions.

## Use one

```sh
tinfoil monitor create personal
tinfoil sandbox create work --monitor personal --ssh
ssh work
```

The CLI generates a workspace key before creation and binds its SHA-256 hash
into the measured boot config as `SANDBOX_OWNER_KEY_SHA256`. It verifies that
config and the shim's attested TLS key before sending the workspace key.
Enrollment accepts only the key matching that boot-bound hash. Starts and
restarts retain the same owner binding.

Enrollment and attestation use the shim's TLS endpoint on port 443. The shim
forwards `/enroll` to the workspace's internal HTTP server on port 8080.
The workspace's `/healthz` endpoint returns an empty readiness response.

With `--monitor`,
workload traffic goes through Monitor. Without it, the sandbox has ordinary
network egress. Private enrollment preserves the shim's TLS; reverse SSH starts after
enrollment supplies Monitor configuration. Both deployments must share a host.
Keep the keys in `~/.tinfoil/sandboxes/<name>` to reopen its disk.

Home directories, `/workspace`, Docker state, and installed packages stay on the
disk. Packages are kept per image build, so an updated image starts without them.
Everything else is reset when the sandbox is recreated.

After enrollment and mounting, `monitor-configure.service` writes this boot's
Monitor configuration under `/run/monitor`. The network and reverse SSH services
wait for it and stay off when enrollment has no Monitor. Systemd supervises the
reverse SSH connection directly and restarts it after disconnects.
