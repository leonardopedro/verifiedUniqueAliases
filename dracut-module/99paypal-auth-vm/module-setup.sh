#!/bin/bash
# module-setup.sh - Dracut module setup script

check() {
    # Always include this module
    return 0
}

depends() {
    # Dependencies on other dracut modules
    # Note: 'network' module doesn't work in containers, so we manually install curl
    echo "base network-manager"
    return 0
}

install() {
    # Use pre-built Rust binary
    BINARY_SOURCE="/app/target/x86_64-unknown-linux-gnu/release/paypal-auth-vm"
    
    if [ ! -f "$BINARY_SOURCE" ]; then
        echo "❌ Binary not found at $BINARY_SOURCE"
        exit 1
    fi
    
    # Install our Rust binary
    inst_simple "$BINARY_SOURCE" /bin/paypal-auth-vm
    find /usr/lib/dracut/modules.d/99paypal-auth-vm -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;
    
    
    # Everything else comes from dracut modules:
    # - "base" module provides: sh, mount, umount, mkdir, etc.
    # - "crypt" module provides: cryptsetup, dm_crypt
    # - "network" module provides: curl (or we'll add it explicitly)
    
    # Add curl if not provided by network module
    if ! dracut_install curl; then
        # Fallback: install from host
        inst_simple /usr/bin/curl /usr/bin/curl
    fi
    
    # Note: dracut automatically handles ALL library dependencies
    # We don't need to manually copy any .so files
    
    # Create directory structure
    # Create directory structure
    inst_dir /run/certs
    inst_dir /tmp/acme-challenge
    
    # Install our custom hook scripts
    # 'cmdline 00': Runs very early, just after kernel command line parsing. 
    # We use this to fetch OCI metadata and set up environment variables before anything else.
    inst_hook cmdline 00 "$moddir/parse-paypal-auth.sh"
    
    # 'pre-pivot 99': Runs at the very end of initramfs execution, just before switching to rootfs.
    # We use this to start our application, effectively replacing the standard init process.
    inst_hook pre-pivot 99 "$moddir/start-app.sh"
}

installkernel() {
    # Install required kernel modules
    instmods virtio_pci virtio_blk
}