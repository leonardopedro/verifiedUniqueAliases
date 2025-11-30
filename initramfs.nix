{ pkgs ? import <nixpkgs> {}, binaryPath ? null }:

let
  # Use pre-built static busybox from nixpkgs
  busybox = pkgs.pkgsStatic.busybox;

  # Create the init script
  initScript = pkgs.writeScript "init" ''
    #!/bin/sh
    set -e
    
    # Mount essential filesystems
    /bin/mkdir -p /proc /sys /dev /run /tmp /var/tmp /var/lib/dhcpcd
    /bin/mount -t proc proc /proc
    /bin/mount -t sysfs sysfs /sys
    /bin/mount -t devtmpfs devtmpfs /dev || true
    
    # Network setup
    echo "Bringing up network..."
    /bin/ip link set lo up
    /bin/ip link set eth0 up
    /bin/dhcpcd eth0
    
    # Metadata fetcher
    fetch_metadata() {
        local key=$1
        /bin/curl -sf -H "Authorization: Bearer Oracle" \
            "http://169.254.169.254/opc/v1/instance/metadata/$key"
    }

    # Wait for metadata service
    echo "Waiting for metadata service..."
    for i in $(/bin/seq 1 30); do
        if /bin/curl -sf http://169.254.169.254/ >/dev/null 2>&1; then
            break
        fi
        /bin/sleep 1
    done

    # Fetch environment variables
    export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
    export DOMAIN=$(fetch_metadata domain)
    export SECRET_OCID=$(fetch_metadata secret_ocid)
    export OCI_REGION=$(/bin/curl -sf http://169.254.169.254/opc/v2/instance/region)
    export NOTIFICATION_TOPIC_ID=$(fetch_metadata notification_topic_id)

    echo "Starting PayPal Auth application..."
    exec /bin/paypal-auth-vm
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
      
      # Network utilities (dynamic - simpler and more reliable)
      { object = "${pkgs.iproute2}/bin/ip"; symlink = "/bin/ip"; }
      { object = "${pkgs.dhcpcd}/bin/dhcpcd"; symlink = "/bin/dhcpcd"; }
      { object = "${pkgs.curl}/bin/curl"; symlink = "/bin/curl"; }
      
      # Copy glibc and essential libraries for dynamic binaries
      { object = "${pkgs.glibc}/lib"; symlink = "/lib"; }
    ];
    
    compressor = "gzip -9";
  };
  
  kernel = pkgs.linuxPackages.kernel;
}
