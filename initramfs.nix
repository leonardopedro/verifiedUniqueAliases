{ pkgs ? import <nixpkgs> {}, binaryPath ? null }:

let
  # 1. USE STATIC PACKAGES
  # This avoids "file not found" errors and library dependency hell inside the initramfs
  busybox = pkgs.pkgsStatic.busybox;
  curl = pkgs.pkgsStatic.curl;
  iproute = pkgs.pkgsStatic.iproute2;
  dhcpcd = pkgs.pkgsStatic.dhcpcd;
  
  # Get kernel version for module paths
  kernel = pkgs.linuxPackages.kernel;
  kernelVersion = kernel.modDirVersion;

  # Create the init script
  initScript = pkgs.writeScript "init" ''
    #!${busybox}/bin/sh

    # Set path to include our static tools
    export PATH=/bin:/sbin

    # Mount essential filesystems
    mkdir -p /proc /sys /dev /run /tmp /var/tmp /etc/ssl/certs
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev || mdev -s

    echo "=== Init System Started ==="

    # Load virtio network drivers (try-catch style)
    # We map the modules to /lib/modules/<ver> so modprobe works natively
    echo "Loading network modules..."
    modprobe virtio_net 2>/dev/null || true
    modprobe virtio_pci 2>/dev/null || true
    modprobe e1000 2>/dev/null || true

    # Network setup - DYNAMIC INTERFACE DETECTION
    echo "Bringing up loopback..."
    ip link set lo up

    echo "Waiting for network interface..."
    INTERFACE=""
    
    # Retry loop to find ANY network interface that isn't lo
    for i in $(seq 1 10); do
        # Find the first interface that starts with 'e' (eth0, enp3s0, ens3, etc.)
        # or just take the first non-loopback device.
        CANDIDATE=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')
        
        if [ -n "$CANDIDATE" ]; then
            INTERFACE=$CANDIDATE
            echo "Found network interface: $INTERFACE"
            break
        fi
        sleep 1
    done

    if [ -n "$INTERFACE" ]; then
        echo "Configuring $INTERFACE..."
        ip link set $INTERFACE up
        
        # Run dhcpcd in foreground first to ensure we get an IP before proceeding
        dhcpcd -1 -t 10 $INTERFACE || echo "DHCP failed, continuing anyway..."
    else
        echo "ERROR: No network interface found. Is -netdev user/tap attached?"
    fi

    # SSL Cert setup for Curl
    export SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt

    # Metadata fetcher
    fetch_metadata() {
        local key=$1
        curl -sf --connect-timeout 2 -H "Authorization: Bearer Oracle" \
            "http://169.254.169.254/opc/v1/instance/metadata/$key" 2>/dev/null || echo "mock-$key"
    }

    # Wait for metadata service (optional)
    echo "Checking metadata service..."
    if curl -sf --connect-timeout 3 http://169.254.169.254/ >/dev/null 2>&1; then
        echo "Metadata service available"
    else
        echo "Metadata service unreachable (skipping wait)"
    fi

    # Fetch environment variables
    export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
    export DOMAIN=$(fetch_metadata domain)
    export SECRET_OCID=$(fetch_metadata secret_ocid)
    
    echo "Starting PayPal Auth application..."
    echo "Target: $DOMAIN"

    if [ -f /bin/paypal-auth-vm ]; then
        chmod +x /bin/paypal-auth-vm
        exec /bin/paypal-auth-vm
    else
        echo "ERROR: /bin/paypal-auth-vm not found"
        echo "Dropping to shell..."
        exec /bin/sh
    fi
  '';

in
{
  initramfs = pkgs.makeInitrd {
    contents = [
      { object = initScript; symlink = "/init"; }
      
      # STATIC TOOLS (No /lib/* hacking required)
      { object = "${busybox}/bin/busybox"; symlink = "/bin/busybox"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/sh"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/mkdir"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/mount"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/sleep"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/cat"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/seq"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/awk"; }  # Added for parsing
      { object = "${busybox}/bin/busybox"; symlink = "/bin/mdev"; } 
      
      # Essential Kernel Tools
      { object = "${pkgs.kmod}/bin/kmod"; symlink = "/bin/modprobe"; }
      
      # Network Tools (Static)
      { object = "${iproute}/bin/ip"; symlink = "/bin/ip"; }
      { object = "${dhcpcd}/bin/dhcpcd"; symlink = "/bin/dhcpcd"; }
      { object = "${curl}/bin/curl"; symlink = "/bin/curl"; }
      
      # CA Certificates (Required for Curl HTTPS)
      { object = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"; symlink = "/etc/ssl/certs/ca-bundle.crt"; }

      # Kernel Modules (Mapped correctly for modprobe)
      # We symlink the specific kernel version folder
      { object = "${kernel}/lib/modules/${kernelVersion}"; symlink = "/lib/modules/${kernelVersion}"; }

    ] ++ pkgs.lib.optionals (binaryPath != null) [
      { object = binaryPath; symlink = "/bin/paypal-auth-vm"; }
    ];
    
    compressor = "gzip -9";
  };
  
  inherit kernel;
}