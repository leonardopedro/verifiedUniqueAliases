{ pkgs ? import <nixpkgs> {}, binaryPath ? null }:

let
  # 1. Static Packages
  busybox = pkgs.pkgsStatic.busybox;
  curl = pkgs.pkgsStatic.curl;
  iproute = pkgs.pkgsStatic.iproute2;
  
  kernel = pkgs.linuxPackages.kernel;
  kernelVersion = kernel.modDirVersion;

  # 2. DHCP Callback Script
  udhcpcScript = pkgs.writeScript "udhcpc.script" ''
    #!/bin/sh
    case "$1" in
      deconfig)
        /bin/ip addr flush dev $interface
        ;;
      bound|renew)
        /bin/ip addr add $ip/$mask dev $interface
        if [ -n "$router" ]; then
           /bin/ip route add default via $router
        fi
        if [ -n "$dns" ]; then
           echo "nameserver $dns" > /etc/resolv.conf
        fi
        ;;
    esac
  '';

  # 3. Main Init Script
  initScript = pkgs.writeScript "init" ''
    #!${busybox}/bin/sh

    export PATH=/bin:/sbin

    # Mount filesystems
    mkdir -p /proc /sys /dev /run /tmp /var/tmp /etc/ssl/certs
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev || mdev -s

    echo "=== Init System Started ==="

    # Load Kernel Modules
    echo "Loading network modules..."
    # REQUIRED for DHCP (Fixes 'Address family not supported')
    modprobe af_packet 2>/dev/null || true
    
    # VirtIO drivers
    modprobe virtio_net 2>/dev/null || true
    modprobe virtio_pci 2>/dev/null || true
    modprobe e1000 2>/dev/null || true
    modprobe virtio_console 2>/dev/null || true

    # Enable Loopback
    ip link set lo up

    # Dynamic Network Interface Detection
    echo "Scanning for network interface..."
    INTERFACE=""
    for i in $(seq 1 10); do
        CANDIDATE=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')
        if [ -n "$CANDIDATE" ]; then
            INTERFACE=$CANDIDATE
            echo "Found interface: $INTERFACE"
            break
        fi
        sleep 1
    done

    if [ -n "$INTERFACE" ]; then
        echo "Configuring $INTERFACE..."
        ip link set $INTERFACE up
        udhcpc -i $INTERFACE -s /bin/udhcpc.script -n -q || echo "DHCP failed"
    else
        echo "ERROR: No network interface found."
    fi

    # Setup SSL for Curl
    export SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt

    # Metadata Helper
    fetch_metadata() {
        local key=$1
        curl -sf --connect-timeout 2 -H "Authorization: Bearer Oracle" \
            "http://169.254.169.254/opc/v1/instance/metadata/$key" 2>/dev/null || echo "example.com"
    }

    # Fetch Vars
    echo "Fetching metadata..."
    export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
    export DOMAIN=$(fetch_metadata domain)
    export SECRET_OCID=$(fetch_metadata secret_ocid)
    export OCI_REGION=$(fetch_metadata region)
    
    echo "Starting PayPal Auth VM..."

    if [ -f /bin/paypal-auth-vm ]; then
        # Check if the binary is executable
        chmod +x /bin/paypal-auth-vm
        
        # Debug info
        echo "Binary found. Attempting execution..."
        
        # Executing...
        exec /bin/paypal-auth-vm || echo "EXEC FAILED: The binary might be dynamically linked. See instructions below."
    else
        echo "Binary not found at /bin/paypal-auth-vm"
    fi

    # Fallback to shell if exec fails or binary missing
    echo "Dropping to emergency shell..."
    exec /bin/sh
  '';

in
{
  initramfs = pkgs.makeInitrd {
    contents = [
      { object = initScript; symlink = "/init"; }
      { object = udhcpcScript; symlink = "/bin/udhcpc.script"; }
      
      # Busybox tools
      { object = "${busybox}/bin/busybox"; symlink = "/bin/busybox"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/sh"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/mkdir"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/mount"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/sleep"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/cat"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/seq"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/awk"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/mdev"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/udhcpc"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/chmod"; }
      { object = "${busybox}/bin/busybox"; symlink = "/bin/ls"; }

      # External Static Tools
      { object = "${pkgs.pkgsStatic.kmod}/bin/kmod"; symlink = "/bin/modprobe"; }
      { object = "${iproute}/bin/ip"; symlink = "/bin/ip"; }
      { object = "${curl}/bin/curl"; symlink = "/bin/curl"; }
      
      # Certificates
      { object = "${pkgs.pkgsStatic.cacert}/etc/ssl/certs/ca-bundle.crt"; symlink = "/etc/ssl/certs/ca-bundle.crt"; }

      # Kernel Modules
      { object = "${kernel}/lib/modules/${kernelVersion}"; symlink = "/lib/modules/${kernelVersion}"; }

    ] ++ pkgs.lib.optionals (binaryPath != null) [
      { object = binaryPath; symlink = "/bin/paypal-auth-vm"; }
    ];
    
    compressor = "gzip -9";
  };
  
  inherit kernel;
}