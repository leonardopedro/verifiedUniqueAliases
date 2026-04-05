#!/bin/bash
# module-setup.sh - Dracut module setup script
# shellcheck disable=SC2154


check() {
    # Always include this module
    return 0
}

depends() {
    # Dependencies on other dracut modules
    # We include 'network' for basic DHCP/networking support
    echo "base network"
    return 0
}

install() {
    # Build Rust binary first
    echo "Building Rust application..."
    cd /app || return 1
    
    # Add target if not already added
    rustup target add x86_64-unknown-linux-gnu 2>/dev/null || true
    
    # Build Rust binary with full reproducibility flags
    # These flags ensure deterministic output:
    # - target-cpu=generic: Avoid host-specific optimizations
    # - codegen-units=1: Single codegen unit for deterministic output
    # - strip=symbols: Strip debug symbols for smaller, deterministic binary
    export RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols"
    
    # Ensure reproducible build with LTO
    export CARGO_PROFILE_RELEASE_LTO=true
    export CARGO_PROFILE_RELEASE_OPT_LEVEL=2
    source /usr/local/cargo/env 
    
    BUILD_TARGET="x86_64-unknown-linux-gnu"
    cargo build --release -j 1 --target $BUILD_TARGET
    
    # Post-process binary for determinism
    # add-det removes non-deterministic metadata (build IDs, timestamps, etc.)
    # and normalizes the binary. RUSTFLAGS already includes strip=symbols, so no
    # additional stripping is needed (and could undo add-det's work).
    add-det target/$BUILD_TARGET/release/paypal-auth-vm
    
    # Normalize the binary timestamp to SOURCE_DATE_EPOCH
    touch -d "@${SOURCE_DATE_EPOCH}" target/$BUILD_TARGET/release/paypal-auth-vm
    find target/$BUILD_TARGET/release -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;
    find /usr/lib/dracut/modules.d/99paypal-auth-vm -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;
    
    # Install our Rust binary (this is the ONLY custom binary we add)
    inst_simple target/$BUILD_TARGET/release/paypal-auth-vm /bin/paypal-auth-vm
    
    # Everything else comes from dracut modules:
    # - "base" module provides: sh, mount, umount, mkdir, etc.
    # - "crypt" module provides: cryptsetup, dm_crypt
    # - "network" module provides: curl (or we'll add it explicitly)
    
    # Add curl if not provided by network module
    if ! dracut_install curl; then
        # Fallback: install from host
        inst_simple /usr/bin/curl /usr/bin/curl
    fi
    
    # Install TPM2 tools and manual networking fallback tools
    dracut_install tpm2_pcrextend tpm2_createprimary tpm2_create tpm2_load tpm2_unseal tpm2_quote tpm2_createak sha256sum awk dhclient ip
    
    # Note: dracut automatically handles ALL library dependencies
    # We don't need to manually copy any .so files
    
    # Create directory structure
    # Create directory structure
    inst_dir /run/certs
    inst_dir /tmp/acme-challenge
    
    # Install our custom hook scripts
    # 'pre-mount 10': Runs after network is fully up and ready (post-initqueue), but 
    # BEFORE Dracut attempts to mount a root. We use this to fetch GCP metadata.
    inst_hook pre-mount 10 "$moddir/parse-paypal-auth.sh"
    
    # 'pre-mount 99': Runs just before Dracut's mount phase.
    # We use this to start our application, replacing PID 1 and skipping pivot/mount entirely.
    inst_hook pre-mount 99 "$moddir/start-app.sh"
    
    # CRITICAL FIX for diskless boot:
    # Dracut's main /init script strictly enforces the presence of a root block device
    # and dies if the variable `rootok` is not set. Because we run ENTIRELY from RAM 
    # and take over PID 1 via pre-pivot 99, there is no root filesystem. 
    # To prevent Dracut from dying and successfully advance through initqueue,
    # we explicitly spoof the root context via our own parsed variables.
    echo "root=tmpfs" > "${initdir}/lib/dracut/hooks/cmdline/99-parse-root.sh"
    echo "rootok=1" >> "${initdir}/lib/dracut/hooks/cmdline/99-parse-root.sh"
    chmod +x "${initdir}/lib/dracut/hooks/cmdline/99-parse-root.sh"
}

installkernel() {
    # Install required kernel modules (virtio for local QEMU, gve for GCP GVNIC)
    instmods virtio_pci virtio_blk virtio_net gve
}