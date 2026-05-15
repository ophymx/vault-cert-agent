#!/bin/sh
set -e

# postinstall — runs after the package files are placed on disk.
# $1 = "configure" on both fresh install and upgrades.
# $2 = (empty on fresh install) | (previous version on upgrade).

case "$1" in
    configure)
        # Create the config directory. AppRole credentials and the
        # config file live here; mode 0700 root:root keeps the
        # role_id / secret_id off other users.
        install -d -m 0700 -o root -g root /etc/vault-cert-agent

        systemctl daemon-reload

        # Enable + start the timer only on first install. On upgrade
        # we leave the existing enabled/disabled state alone — an
        # operator may have deliberately disabled it.
        if [ -z "$2" ]; then
            systemctl enable --now vault-cert-agent.timer || true
        fi
        ;;
esac

exit 0
