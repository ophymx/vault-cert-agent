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

        # On first install, enable + start the single-instance timer
        # only when a default config.hcl already exists — typical when
        # configuration management drops the package + config together.
        # Hosts that use only templated instances
        # (vault-cert-agent@<name>.timer) deliberately have no
        # /etc/vault-cert-agent/config.hcl; we mustn't fire a timer
        # that's guaranteed to fail. Upgrades leave existing
        # enabled/disabled state alone.
        if [ -z "$2" ] && [ -f /etc/vault-cert-agent/config.hcl ]; then
            systemctl enable --now vault-cert-agent.timer || true
        fi
        ;;
esac

exit 0
