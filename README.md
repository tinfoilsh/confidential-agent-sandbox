# Confidential Agent Sandbox

An Ubuntu VM with Docker, encrypted storage, and network access through Monitor.

Create a Monitor and sandbox in the dashboard, then connect:

```sh
tinfoil attest-ssh work --install
ssh work
```

Rerun `attest-ssh` after either VM reboots. Back up the CLI's encryption credentials.
