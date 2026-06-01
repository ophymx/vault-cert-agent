#!/bin/sh
set -e

# preremove — runs before the package files are removed.
# $1 = "remove" on uninstall, "upgrade" during an upgrade, "purge"
# when finishing a purge that wasn't preceded by remove.

stop_and_disable() {
    unit="$1"
    if systemctl is-active "$unit" >/dev/null 2>&1; then
        systemctl stop "$unit" || true
    fi
    if systemctl is-enabled "$unit" >/dev/null 2>&1; then
        systemctl disable "$unit" || true
    fi
}

case "$1" in
    remove|purge)
        stop_and_disable vault-cert-agent.timer
        # Templated instances enabled by operators get symlinked into
        # timers.target.wants. Walk those so we don't leave a timer
        # firing at a soon-to-be-missing binary or, on purge, an
        # rm-rf'd /etc/vault-cert-agent/<instance>/.
        for link in /etc/systemd/system/timers.target.wants/vault-cert-agent@*.timer; do
            [ -e "$link" ] || continue
            stop_and_disable "$(basename "$link")"
        done
        ;;
    upgrade)
        # systemd state is preserved across upgrades; postinstall
        # will daemon-reload after the new files are in place.
        ;;
esac

exit 0
