#!/bin/bash
# Mint this boot's SSH credentials, unlock the disk, mount its state, and start systemd.
set -euo pipefail

disk=/mnt/disk
credentials=/run/workspace

umask 022
install -d -m 0711 "$credentials"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$credentials/host_key"
[[ -S /run/tinfoil/volumes/workspace/control.sock ]] && /usr/local/libexec/workspace-enroll
# sshd opens the enrolled key as the login user.
install -m 0644 "$disk/.authorized_keys" "$credentials/authorized_keys"
# The pack names its closure without the hash here, which is what nix.conf reads.
install -d /nix/var/nix/profiles
ln -sfn /tinfoil/models/nix/nix/var/nix/profiles/default /nix/var/nix/profiles/default
[[ -s $disk/machine-id ]] || systemd-id128 new > "$disk/machine-id"
[[ -d $disk/home ]] || cp -a /home "$disk/home"
[[ -d $disk/workspace ]] || install -d -o sandbox -g sandbox "$disk/workspace"
# Keyed by the image's package set, so a rebuilt image starts from a clean layer.
overlay=$disk/overlay/$(sha256sum /var/lib/dpkg/status | cut -c1-16)
mount --make-rprivate /
for dir in usr etc var opt; do
    install -d "$overlay/$dir/upper" "$overlay/$dir/work" /run/overlay
    mount -t overlay overlay -o "lowerdir=/$dir,upperdir=$overlay/$dir/upper,workdir=$overlay/$dir/work" /run/overlay
    # Runtime mounts such as resolv.conf and GPU libraries live under these directories.
    while IFS= read -r target; do
        printf -v target %b "$target"
        mount --rbind "$target" "/run/overlay${target#/"$dir"}"
    done < <(findmnt -rn -o TARGET | grep "^/$dir/")
    mount --move /run/overlay "/$dir"
done
mount --bind "$disk/machine-id" /etc/machine-id
mount --bind "$disk/home" /home
mount --bind "$disk/workspace" /workspace
# Leave device management with the CVM, while its cgroup submount stays writable.
mount -o remount,bind,ro /sys
exec /sbin/init
