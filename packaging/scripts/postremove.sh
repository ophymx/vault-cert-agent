#!/bin/sh
set -e

# postremove — runs after the package files are removed.
# $1 = "remove" on uninstall, "purge" when purging, "upgrade" during
# an upgrade. Credentials live under /etc/vault-cert-agent/ and are
# preserved across remove/upgrade; only purge clears them.

case "$1" in
    purge)
        # /etc/vault-cert-agent/ holds the AppRole role_id/secret_id
        # and config.hcl, all created by postinstall (the ghost dir).
        # apt purge means the operator wants the package gone; leaving
        # the AppRole credentials behind is a footgun.
        rm -rf /etc/vault-cert-agent
        ;;
esac

exit 0
