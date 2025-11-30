{ pkgs ? import <nixpkgs> {}, binaryPath ? null }:

let
  # Use pre-built static busybox from nixpkgs
  busybox = pkgs.pkgsStatic.busybox;

  # Create the init script
  initScript = pkgs.writeScript "init" ''
    #!/bin/sh
    
    # Mount essential filesystems
    /bin/mkdir -p /proc /sys /dev /run /tmp /var/tmp /var/lib/dhcpcd
    /bin/mount -t proc proc /proc
    /bin/mount -t sysfs sysfs /sys
    /bin/mount -t devtmpfs devtmpfs /dev || true
    
    # Load virtio network drivers
    echo "Loading virtio network drivers..."
    export MODULE_DIR=/modules
    /bin/modprobe -d /modules virtio_pci 2>/dev/null || true
    /bin/modprobe -d /modules virtio_net 2>/dev/null || true
    /bin/sleep 2
    
    # Network setup - be resilient to missing interfaces
    echo "Bringing up network..."
    /bin/ip link set lo up || true
    
    # Wait for eth0 to appear (QEMU virtio-net may take time)
    for i in $(/bin/seq 1 10); do
        if /bin/ip link show eth0 >/dev/null 2>&1; then
            echo "Found eth0, configuring..."
            /bin/ip link set eth0 up
            /bin/dhcpcd eth0 &
            break
        fi
        echo "Waiting for eth0... ($i/10)"
        /bin/sleep 1
    done
    
    if ! /bin/ip link show eth0 >/dev/null 2>&1; then
        echo "WARNING: eth0 not found. Network will not be available."
        echo "To enable networking, run QEMU with: -nic user,model=virtio-net-pci"
    fi
    
    # Metadata fetcher
    fetch_metadata() {
        local key=$1
        /bin/curl -sf -H "Authorization: Bearer Oracle" \
            "http://169.254.169.254/opc/v1/instance/metadata/$key" 2>/dev/null || echo "mock-$key"
    }

    # Wait for metadata service (optional)
    echo "Waiting for metadata service..."
    for i in $(/bin/seq 1 10); do
        if /bin/curl -sf http://169.254.169.254/ >/dev/null 2>&1; then
            echo "Metadata service available"
            break
        fi
        /bin/sleep 1
    done

    # Fetch environment variables (with fallbacks for testing)
    export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
    export DOMAIN=$(fetch_metadata domain)
    export SECRET_OCID=$(fetch_metadata secret_ocid)
    export OCI_REGION=$(/bin/curl -sf http://169.254.169.254/opc/v2/instance/region 2>/dev/null || echo "mock-region")
    export NOTIFICATION_TOPIC_ID=$(fetch_metadata notification_topic_id)

    echo "Starting PayPal Auth application..."
    echo "Environment:"
    echo "  PAYPAL_CLIENT_ID: $PAYPAL_CLIENT_ID"
    echo "  DOMAIN: $DOMAIN"
    echo ""
    
    if [ -f /bin/paypal-auth-vm ]; then
        exec /bin/paypal-auth-vm
    else
        echo "ERROR: /bin/paypal-auth-vm not found"
        echo "Dropping to shell for debugging..."
        exec /bin/sh
    fi
  '';

in
{
  initramfs = pkgs.makeInitrd {
    contents = [
      # Init script
      { object = initScript; symlink = "/init"; }
      
      # Application binary (if provided)
    ] ++ pkgs.lib.optionals (binaryPath != null) [
      { object = binaryPath; symlink = "/bin/paypal-auth-vm"; }
    ] ++ [
      # Essential utilities from busybox
      { object = "${busybox}/bin/busybox"; symlink = "/bin/busybox"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/sh"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/mkdir"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/mount"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/sleep"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/cat"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/seq"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/modprobe"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/insmod"; }
      
      # Network utilities (dynamic - simpler and more reliable)
      { object = "${pkgs.iproute2}/bin/ip"; symlink = "/bin/ip"; }
      { object = "${pkgs.dhcpcd}/bin/dhcpcd"; symlink = "/bin/dhcpcd"; }
      { object = "${pkgs.curl}/bin/curl"; symlink = "/bin/curl"; }
      
      # Copy glibc and essential libraries for dynamic binaries
      { object = "${pkgs.glibc}/lib"; symlink = "/lib"; }
      
      # Kernel modules for virtio network support (at /modules to avoid conflict with /lib)
      { object = "${pkgs.linuxPackages.kernel}/lib/modules"; symlink = "/modules"; }
    ];
    
    compressor = "gzip -9";
  };
  
  kernel = pkgs.linuxPackages.kernel;
}
