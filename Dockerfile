# syntax=docker/dockerfile:1

# There is no go.mod: the permit check is stdlib ECDSA over a JWS and the SSH
# credential is three length-prefixed strings, so main.go is the whole program
# and the build fetches nothing for it.
FROM golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
COPY main.go /src/
WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' -o /confidential-agent-sandbox main.go

# OpenSSH is a C program with a shell behind it, so the runtime is Alpine rather
# than distroless. The Go half is still the only thing this repo authors; what
# Alpine contributes is audited the way every other measured container is -- by
# the image digest tinfoil-config pins, which covers this base, these packages,
# and the accounts declared below.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
RUN apk add --no-cache openssh-server openssh-keygen \
    # The login account owns nothing but its home on the workspace volume.
 && adduser -D -H -u 1000 -h /home/sandbox -s /bin/sh sandbox \
    # Dangles until an enrollment unlocks the volume, which is before anything follows it.
 && ln -s /workspace/home /home/sandbox \
    # Must stay a real directory: nix refuses a store reached through a symlink.
 && mkdir /nix \
    # Nothing here can move to a flag: nix builds through a hook that re-reads only this file.
 && mkdir -p /etc/nix \
 && printf '%s\n' \
    'experimental-features = nix-command flakes local-overlay-store read-only-local-store' \
    'store = local-overlay://?root=/&lower-store=local%3Froot%3D%2Ftinfoil%2Fmodels%2Fnix%26read-only%3Dtrue&upper-layer=/nix/store.upper&check-mount=false' \
    # Resolves nixpkgs to the tree the pack was built from, so what it holds is never fetched again.
    'flake-registry = /nix/var/nix/profiles/default/etc/nix/registry.json' \
    'build-users-group =' \
    'sandbox = false' \
    'substituters = https://cache.nixos.org' \
    > /etc/nix/nix.conf \
    # Alpine's /etc/profile assigns PATH before it reads this directory, so the
    # toolchain is put back here. Both scripts ship in the pack: nix's own puts the
    # profile on PATH, the sandbox one sets what a store path cannot bake in.
 && printf '%s\n' \
    '. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh' \
    '. /nix/var/nix/profiles/default/etc/profile.d/50-sandbox.sh' \
    > /etc/profile.d/nix.sh \
    # Scripts hardcode both, and the pack is mounted at /nix, so they are the image's to provide.
 && ln -s /nix/var/nix/profiles/default/bin/bash /bin/bash \
 && ln -sf /nix/var/nix/profiles/default/bin/env /usr/bin/env \
    # sshd refuses a login for an account whose password field is locked, even
    # for publickey, so the field is set to a value no password can hash to
    # instead of the `!` adduser leaves. Password authentication is refused by
    # the policy in main.go regardless; this is what keeps publickey reachable.
 && sed -i 's|^sandbox:[^:]*:|sandbox:$6$sealed$sandbox:|' /etc/shadow \
    # No image ships a host key: main.go mints one per boot into a tmpfs, and
    # /etc/ssh/sshd_config is never read because sshd is started with -f.
 && rm -f /etc/ssh/sshd_config /etc/ssh/ssh_host_*
COPY --from=build /confidential-agent-sandbox /confidential-agent-sandbox
EXPOSE 8080 22
ENTRYPOINT ["/confidential-agent-sandbox"]
