# Confidential Agent Sandbox

An Ubuntu workspace in a confidential VM with Docker and persistent encrypted storage.
Create a Monitor and sandbox in the dashboard using compatible releases and your
Ed25519 SSH public key, then run:

```sh
tinfoil attest-ssh work --install
ssh work
```

Rerun `attest-ssh` after either VM reboots; restart the sandbox if Monitor's address
or network grant changed. Back up the CLI's encryption credentials. Deletion retains
the billable workspace volume; changing Monitor is unsupported.

Bootstrap relays public attestation; secrets travel over attested, pinned SSH.
