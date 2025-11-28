#!/bin/bash
# module-setup.sh - Dracut module setup script

check() {
    # Always include this module
    return 0
}

depends() {
    # Dependencies on other dracut modules
    # Note: 'network' module doesn't work in containers, so we manually install curl
    echo "base"
    return 0
}

install() {
    # Build Rust binary first
    echo "Building Rust application..."
    cd /app
    
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
    cargo build --release --target $BUILD_TARGET
    
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