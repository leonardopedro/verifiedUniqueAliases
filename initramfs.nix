{ pkgs ? import <nixpkgs> {}, binaryPath }:

let
  # Use static packages for standalone tools
  static = pkgs.pkgsStatic;
  
  initScript = pkgs.writeScript "init" ''
    #!${static.bash}/bin/bash
    
    export PATH=/bin
    
    # Mount filesystems
    mkdir -p /proc /sys /dev /run /tmp /var/tmp /etc/ssl/certs /var/lib/dhcpcd
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    
    # Basic network setup
    echo "Bringing up network..."
    ip link set lo up
    ip link set eth0 up
    # Static IP or DHCP? The original script used dracut's network module.
    # We'll assume simple DHCP is needed, but standard iproute2 doesn't have a DHCP client.
    # We might need a standalone dhcp client if not using busybox's udhcpc.
    # For OCI, we often get IP via DHCP. 
    # Let's try to use 'dhcpcd' if available static, or just rely on the fact that 
    # in some OCI environments, we might need to configure it.
    # Actually, without busybox/udhcpc, we need a DHCP client. 
    # 'dhcpcd' is a good choice.
    dhcpcd eth0
    
    # Metadata fetcher using curl
    fetch_metadata() {
        local key=$1
        curl -sf -H "Authorization: Bearer Oracle" \
            "http://169.254.169.254/opc/v1/instance/metadata/$key"
    }

    # Wait for metadata service
    echo "Waiting for metadata service..."
    # Loop a few times
    for i in $(seq 1 30); do
        if curl -sf http://169.254.169.254/ >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # Fetch env vars
    export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
    export DOMAIN=$(fetch_metadata domain)
    export SECRET_OCID=$(fetch_metadata secret_ocid)
    export OCI_REGION=$(curl -sf http://169.254.169.254/opc/v2/instance/region)
    export NOTIFICATION_TOPIC_ID=$(fetch_metadata notification_topic_id)

    echo "Starting PayPal Auth application..."
    exec /bin/paypal-auth-vm
  '';

in
{
  initramfs = pkgs.makeInitrd {
    contents = [
      { object = initScript; symlink = "/init"; }
      { object = binaryPath; symlink = "/bin/paypal-auth-vm"; }
      
      # Shell
      { object = "${static.bash}/bin/bash"; symlink = "/bin/bash"; }
      { object = "${static.bash}/bin/sh"; symlink = "/bin/sh"; }
      
      # Coreutils (mkdir, sleep, seq, etc.)
      { object = "${static.coreutils}/bin/mkdir"; symlink = "/bin/mkdir"; }
      { object = "${static.coreutils}/bin/sleep"; symlink = "/bin/sleep"; }
      { object = "${static.coreutils}/bin/seq"; symlink = "/bin/seq"; }
      { object = "${static.coreutils}/bin/cat"; symlink = "/bin/cat"; }
      
      # Util-linux (mount)
      { object = "${static.util-linux}/bin/mount"; symlink = "/bin/mount"; }
      
      # Network
      { object = "${static.iproute2}/bin/ip"; symlink = "/bin/ip"; }
      { object = "${static.dhcpcd}/bin/dhcpcd"; symlink = "/bin/dhcpcd"; }
      { object = "${static.curl}/bin/curl"; symlink = "/bin/curl"; }
      
      # Certs
      { object = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"; symlink = "/etc/ssl/certs/ca-certificates.crt"; }
    ];
  };
  
  # Export the kernel so the build script can find it
  kernel = pkgs.linux;
}
