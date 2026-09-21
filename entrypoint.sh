#!/bin/bash
# Seed a persistent Ubuntu root, carry runtime mounts into it, and start systemd.
set -euo pipefail

disk=/mnt/disk
credentials=/run/workspace
control=/run/tinfoil/volumes/workspace/control.sock

fail() { printf 'sandbox: %s\n' "$*" >&2; exit 1; }

stage_credentials() {
    install -d -m 0711 "$credentials"
    ssh-keygen -q -t ed25519 -N '' -C '' -f "$credentials/host_key"
}

unlock_workspace() {
    [[ -S $control ]] || return 0
    /usr/local/libexec/workspace-enroll
}

seed_root() (
    # Hold the lock only while installing the OS.
    umask 077
    exec 9> "$disk/.rootfs.lock"
    flock -x 9
    umask 022
    root=$disk/rootfs
    if [[ ! -e $root ]]; then
        staging=$disk/.rootfs.new
        # An interrupted copy must never become the installed OS.
        rm -rf -- "$staging"
        install -d -m 0755 "$staging"
        rsync -aHAXx --numeric-ids \
            --exclude='/mnt/disk/***' --exclude='/proc/***' --exclude='/sys/***' \
            --exclude='/dev/***' --exclude='/run/***' --exclude='/tinfoil/***' / "$staging/"
        mkdir -p "$staging"/{dev,proc,sys,run,tinfoil,mnt/disk,workspace}
        machine_id=$(< /proc/sys/kernel/random/uuid)
        machine_id=${machine_id//-/}
        [[ $machine_id =~ ^[0-9a-f]{32}$ ]] || fail 'invalid kernel-generated machine ID'
        hostname=workspace-${machine_id:0:12}
        printf '%s\n' "$machine_id" > "$staging/etc/machine-id"
        printf '%s\n' "$hostname" > "$staging/etc/hostname"
        printf '127.0.0.1 localhost\n127.0.1.1 %s\n::1 localhost ip6-localhost ip6-loopback\n' "$hostname" > "$staging/etc/hosts"
        printf '1\n' > "$staging/.workspace-root-version"
        sync -f "$disk"
        mv -T -- "$staging" "$root"
        sync -f "$disk"
    fi
    [[ $(< "$root/.workspace-root-version") == 1 ]] || fail 'unsupported persistent root version'
    mkdir -p "$disk/workspace" "$disk/docker"
)

read_mounts() {
    local inventory encoded target parent
    # Raw findmnt output hex-escapes whitespace and backslashes. Decode once,
    # after sorting, so even paths containing newlines stay intact in the array.
    inventory=$(findmnt --kernel --tab-file "$1" --raw --noheadings --output TARGET | LC_ALL=C sort -u)
    mounts=()
    while IFS= read -r encoded; do
        printf -v target '%b' "$encoded"
        case $target in
            /|"$disk"|"$disk"/*|/etc/hostname|/etc/hosts) continue ;;
        esac
        for parent in "${mounts[@]}"; do
            # A moved parent carries its children, including writable cgroups.
            [[ $target == "$parent"/* ]] && continue 2
        done
        mounts+=("$target")
    done <<< "$inventory"
}

prepare_mountpoint() {
    local destination=$1$2 target=$2
    # Replace persisted absolute symlinks before installing runtime file mounts.
    if [[ -L $destination ]]; then rm -- "$destination"; fi
    if [[ -d $target ]]; then
        mkdir -p -- "$destination"
    else
        mkdir -p -- "${destination%/*}"
        touch -- "$destination"
    fi
}

migrate_ssh_settings() {
    # Existing persistent roots retain the old image's SSH and health settings.
    sed -i 's/^Port 2222$/Port 22/' "$1/etc/ssh/sshd_config"
    sed -i 's|^AuthorizedKeysFile .ssh/authorized_keys .ssh/tinfoil_authorized_keys$|AuthorizedKeysFile /run/workspace/authorized_keys|' "$1/etc/ssh/sshd_config"
    sed -i 's|/dev/tcp/127.0.0.1/2222\b|/dev/tcp/127.0.0.1/22|g' "$1/healthcheck.sh"
}

boot() {
    [[ $# == 0 ]] || { printf 'usage: /entrypoint\n' >&2; exit 2; }
    [[ $$ == 1 ]] || fail 'the entrypoint must run as PID 1'
    umask 077
    stage_credentials
    unlock_workspace
    mountpoint -q "$disk" || fail '/mnt/disk must be the mounted encrypted volume'
    # sshd opens the enrolled key as the login user.
    install -m 0644 "$disk/.authorized_keys" "$credentials/authorized_keys"
    # Run this image's helper even when the persistent root is from an older image.
    install -m 0700 /usr/local/libexec/workspace-init "$credentials/init"
    seed_root
    migrate_ssh_settings "$disk/rootfs"
    umask 022
    local root=$disk/rootfs target
    read_mounts /proc/self/mountinfo
    # Do not update /run/mount/utab while moving /run itself out of this root.
    mount -n --make-rprivate /
    mount -n --bind "$root" "$root"
    # The encrypted volume is nosuid. Ubuntu's sudo needs suid on its root bind.
    mount -n -o remount,bind,suid,nodev "$root"
    for target in "${mounts[@]}"; do prepare_mountpoint "$root" "$target"; done
    mkdir -p "$root$disk" "$root/workspace" "$root/.oldroot"
    mount -n --bind "$disk" "$root$disk"
    mount -n --bind "$disk/workspace" "$root/workspace"
    for target in "${mounts[@]}"; do mount -n --move "$target" "$root$target"; done
    cd "$root"
    pivot_root . .oldroot
    exec chroot . /bin/bash /run/workspace/init
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then boot "$@"; fi
