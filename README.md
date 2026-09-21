# Confidential Agent Sandbox

An Ubuntu 24.04 workspace inside a confidential VM. It has systemd, its own
Docker daemon, and an encrypted disk that keeps your files between sessions.

## Use one

```sh
tinfoil sandbox create workspace
tinfoil sandbox ssh workspace
```

The first connection puts the keys to the sandbox in `~/.tinfoil/sandboxes/<name>`, and seals the disk with them.

Apt packages, home directories, `/workspace`, and Docker state stay on the disk.
