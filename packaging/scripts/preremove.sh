#!/bin/sh
set -e

# preremove — runs before the package files are removed.
# $1 = "remove" on uninstall, "upgrade" during an upgrade, "purge"
# when finishing a purge that wasn't preceded by remove.

case "$1" in
    remove|purge)
        if systemctl is-active vault-cert-agent.timer >/dev/null 2>&1; then
            systemctl stop vault-cert-agent.timer || true
        fi
        if systemctl is-enabled vault-cert-agent.timer >/dev/null 2>&1; then
            systemctl disable vault-cert-agent.timer || true
        fi
        ;;
    upgrade)
        # systemd state is preserved across upgrades; postinstall
        # will daemon-reload after the new files are in place.
        ;;
esac

exit 0
