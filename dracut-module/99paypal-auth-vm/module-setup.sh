#!/bin/bash

# dracut module setup script for paypal-auth-vm

# Called by dracut to check if the module should be included.
check() {
    # Always include this module.
    return 0
}

# Called by dracut to list module dependencies.
depends() {
    # Add any modules your custom module depends on.
    # e.g. echo " network base shutdown "
    return 0
}

# Called by dracut to install the module files.
install() {
    # Install the main rust binary.
    # The path /home/user/verifieduniquealiases/target/x86_64-unknown-linux-musl/release/paypal-auth-vm
    # is a placeholder that will be replaced by the build script.
    inst_simple "/home/user/verifieduniquealiases/target/x86_64-unknown-linux-musl/release/paypal-auth-vm" "/usr/bin/paypal-auth-vm"

    # Install the helper script.
    inst_simple "$moddir/init-disk.sh" "/usr/bin/init-disk.sh"
}
#!/bin/bash
# module-setup.sh - Dracut module setup script

check() {
    # Always include this module
    return 0
}

depends() {
    # Dependencies on other dracut modules
    # These modules provide essential binaries and functionality
    echo "base network crypt"
    return 0
}

install() {
    # Build Rust binary first
    echo "Building Rust application..."
    cd /home/user/verifieduniquealiases
    cargo build --release --target x86_64-unknown-linux-musl
    strip target/x86_64-unknown-linux-musl/release/paypal-auth-vm
    
    # Install our Rust binary (this is the ONLY custom binary we add)
    inst_simple /home/user/verifieduniquealiases/target/x86_64-unknown-linux-musl/release/paypal-auth-vm \
        /bin/paypal-auth-vm
    
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
    inst_dir /mnt/encrypted
    inst_dir /run/certs
    inst_dir /tmp/acme-challenge
    
    # Install LUKS key (embedded in initramfs - part of measured boot)
    inst_simple /build/luks.key /etc/luks.key
    chmod 600 "${initdir}/etc/luks.key"
    
    # Install our custom hook scripts
    inst_hook cmdline 00 "$moddir/parse-paypal-auth.sh"
    inst_hook pre-mount 50 "$moddir/mount-encrypted.sh"
    inst_hook pre-pivot 99 "$moddir/start-app.sh"
    inst_hook shutdown 50 "$moddir/save-cert.sh"
}

installkernel() {
    # Install required kernel modules
    instmods virtio_pci virtio_blk dm_crypt
}