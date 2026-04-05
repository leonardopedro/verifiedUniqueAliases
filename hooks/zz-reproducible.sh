#!/bin/sh
set -e

PREREQ=""
prereqs() {
    echo "$PREREQ"
}

case $1 in
    prereqs)
        prereqs
        exit 0
        ;;
esac

# Normalize timestamps and remove random metadata
# This hook runs after other hooks to clean up the initramfs
# 1. Remove non-deterministic files
rm -f "${DESTDIR}/etc/machine-id"
rm -f "${DESTDIR}/var/lib/dbus/machine-id"
rm -f "${DESTDIR}/var/lib/systemd/random-seed"

# 2. Reset timestamps to SOURCE_DATE_EPOCH
if [ -n "$SOURCE_DATE_EPOCH" ]; then
    find "${DESTDIR}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
fi
