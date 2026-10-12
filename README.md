# Confidential Agent Sandbox

An Ubuntu 24.04 workspace inside a confidential VM. It has systemd, its own
Docker daemon, and an encrypted disk that keeps your files between sessions.

## Use one

```sh
tinfoil monitor create personal
tinfoil sandbox create work --monitor personal --ssh
ssh work
```

Supply a workspace passphrase or reuse a saved workspace key. Passphrases are
16 to 4096 UTF-8 bytes; spaces and newlines are part of the secret. The dashboard
and CLI bind a salted Argon2id commitment into the measured boot config as
`SANDBOX_OWNER_KEY_ARGON2ID`. Enrollment verifies it before sending the unchanged
secret to RC3's Argon2id volume worker. Clients verify that config and the shim's
attested TLS key before sending the secret. Starts and restarts keep the binding.

The commitment uses standard PHC encoding with Argon2id v19, 256 MiB memory,
three passes, four lanes, a random 32-byte salt, and a 32-byte verifier. The disk
uses its own independent salt. Existing 64-byte generated credentials and their
`SANDBOX_OWNER_KEY_SHA256` bindings still work. Exactly one owner binding must be
set. Base64 is only the enrollment transport encoding; passphrases need no
special encoding.

Enrollment and attestation use the shim's TLS endpoint on port 443. The shim
forwards `/enroll` to the workspace's internal HTTP server on port 8080.
The workspace's `/healthz` endpoint returns an empty readiness response.

With `--monitor`,
workload traffic goes through Monitor. Without it, the sandbox has ordinary
network egress. Private enrollment preserves the shim's TLS; reverse SSH starts after
enrollment supplies Monitor configuration. The control plane permits the sandbox to reach its assigned Monitor, including
when they run on separate hosts.
Keep the keys in `~/.tinfoil/sandboxes/<name>` to reopen its disk.

Home directories, `/workspace`, Docker state, and installed packages stay on the
disk. Packages are kept per image build, so an updated image starts without them.
Everything else is reset when the sandbox is recreated.

After enrollment and mounting, `monitor-configure.service` writes this boot's
Monitor configuration under `/run/monitor`. The network and reverse SSH services
wait for it and stay off when enrollment has no Monitor. Systemd supervises the
reverse SSH connection directly and restarts it after disconnects.
