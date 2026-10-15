# syntax=docker/dockerfile:1.6
#
# Confidential Ubuntu: a measured, CVM-admin interactive workspace.
# The base is digest-pinned for attestation.
#
# cvm_admin supplies the privileges for the inner daemon, not a host socket.
ARG BASE_IMAGE=docker.io/library/ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254

FROM golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
COPY go.mod *.go /src/
WORKDIR /src
RUN go test ./...
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' -o /workspace-attestation .

FROM ${BASE_IMAGE}
ENV container=docker LANG=en_US.UTF-8
ARG DOCKER_VERSION=29.6.2
ARG DOCKER_SHA256=d6204aea92238e2453d5445c885b9d2e5eb8f82915568ec50edf9dbe12a3ac74
ARG BUILDX_VERSION=0.37.1
ARG BUILDX_SHA256=9447199cdb435f25880548343c128a4b6650e8891ee598905d8d29d39a8e359b
ARG SING_BOX_VERSION=1.14.3
ARG SING_BOX_SHA256=e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee

RUN yes | DEBIAN_FRONTEND=noninteractive unminimize \
    && rm -f /etc/dpkg/dpkg.cfg.d/docker-apt-speedup \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      pciutils \
      curl \
      git \
      less \
      vim-tiny \
      python3 \
      python3-venv \
      python3-pip \
      rsync htop tmux openssh-server iproute2 procps nftables \
      systemd systemd-sysv dbus dbus-user-session libpam-systemd \
      sudo man-db manpages bash-completion locales dnsutils iputils-ping \
      cron logrotate util-linux \
    && locale-gen en_US.UTF-8 \
    && usermod -l sandbox -d /home/sandbox -m ubuntu && groupmod -n sandbox ubuntu \
    && groupadd -f docker \
    && usermod -aG sudo,adm,systemd-journal,docker -s /bin/bash sandbox \
    && passwd -l sandbox \
    && mkdir /workspace \
    && rm -f /usr/sbin/policy-rc.d \
    # Must stay a real directory: nix refuses a store reached through a symlink.
    && mkdir /nix \
    # Nothing here can move to a flag: nix builds through a hook that re-reads only this file.
    && mkdir -p /etc/nix \
    && printf '%s\n' \
      'experimental-features = nix-command flakes local-overlay-store read-only-local-store' \
      'store = local-overlay://?root=/&lower-store=local%3Froot%3D%2Ftinfoil%2Fmodels%2Fnix%26read-only%3Dtrue&upper-layer=/nix/store.upper&check-mount=false' \
      'flake-registry = /nix/var/nix/profiles/default/etc/nix/registry.json' \
      'build-users-group =' \
      'sandbox = false' \
      'substituters = https://cache.nixos.org' \
      > /etc/nix/nix.conf \
    && printf '%s\n' \
      '. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh' \
      '. /nix/var/nix/profiles/default/etc/profile.d/50-sandbox.sh' \
      '[ "$(id -u)" = 0 ] || export NIX_CONFIG="store = daemon"' \
      > /etc/profile.d/nix.sh \
    && rm -f /etc/ssh/ssh_host_* \
    # PAM displays our static /etc/motd instead of Ubuntu's generated welcome.
    && rm -f /etc/update-motd.d/* /run/motd.dynamic \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL --retry 3 "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" -o /tmp/docker.tgz \
    && echo "${DOCKER_SHA256}  /tmp/docker.tgz" | sha256sum -c - \
    && tar -xzf /tmp/docker.tgz --strip-components=1 -C /usr/local/bin \
    && rm /tmp/docker.tgz \
    && mkdir -p /usr/local/lib/docker/cli-plugins \
    && curl -fsSL --retry 3 "https://github.com/docker/buildx/releases/download/v${BUILDX_VERSION}/buildx-v${BUILDX_VERSION}.linux-amd64" -o /usr/local/lib/docker/cli-plugins/docker-buildx \
    && echo "${BUILDX_SHA256}  /usr/local/lib/docker/cli-plugins/docker-buildx" | sha256sum -c - \
    && chmod 0755 /usr/local/lib/docker/cli-plugins/docker-buildx

RUN curl -fsSL --retry 3 "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-amd64.tar.gz" -o /tmp/sing-box.tar.gz \
    && echo "${SING_BOX_SHA256}  /tmp/sing-box.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/sing-box.tar.gz --strip-components=1 -C /usr/local/bin "sing-box-${SING_BOX_VERSION}-linux-amd64/sing-box" \
    && mkdir -p /usr/local/share/licenses/sing-box \
    && tar -xOzf /tmp/sing-box.tar.gz "sing-box-${SING_BOX_VERSION}-linux-amd64/LICENSE" > /usr/local/share/licenses/sing-box/LICENSE \
    && rm /tmp/sing-box.tar.gz

COPY --chmod=0755 entrypoint.sh /entrypoint
COPY rootfs/ /
COPY --from=build /workspace-attestation /usr/local/libexec/workspace-attestation
ARG SANDBOX_VERSION=dev
RUN sed -i "s/<VERSION>/${SANDBOX_VERSION}/" /etc/motd \
    && chmod 0440 /etc/sudoers.d/90-sandbox \
    && chmod 0755 /usr/local/libexec/workspace-keys /usr/local/bin/workspace-unlock /usr/local/bin/monitor /usr/local/libexec/seed-agent-skills /usr/local/libexec/seed-agent-config /usr/local/libexec/enable-tinfoil \
    && for script in /entrypoint /healthcheck.sh /usr/local/libexec/seed-agent-skills /usr/local/libexec/enable-tinfoil /etc/profile.d/zz-monitor.sh; do \
         bash -n "$script" || exit 1; \
       done \
    && /usr/local/bin/monitor run --help > /dev/null \
    && /usr/local/bin/monitor mcp serve --help > /dev/null \
    && /usr/local/bin/monitor network --help > /dev/null \
    && /usr/local/bin/monitor enable --help > /dev/null

RUN systemctl disable ssh.socket \
    && systemctl enable ssh.service docker.service cron.service monitor-network.service monitor-reverse.service workspace-attestation.service \
    # The units resolve once the entrypoint links the pack's profile, so systemctl cannot enable them here.
    && ln -s /nix/var/nix/profiles/default/lib/systemd/system/nix-daemon.service \
         /nix/var/nix/profiles/default/lib/systemd/system/nix-daemon.socket /etc/systemd/system/ \
    && mkdir -p /etc/systemd/system/sockets.target.wants \
    && ln -s /etc/systemd/system/nix-daemon.socket /etc/systemd/system/sockets.target.wants/ \
    && systemctl mask systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket \
         systemd-networkd.service systemd-networkd.socket systemd-networkd-wait-online.service \
         systemd-resolved.service systemd-timesyncd.service console-getty.service \
    && systemctl set-default multi-user.target \
    && rm -f /etc/machine-id /var/lib/dbus/machine-id \
    && touch /etc/machine-id \
    && ln -s /etc/machine-id /var/lib/dbus/machine-id

EXPOSE 22
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/entrypoint"]
