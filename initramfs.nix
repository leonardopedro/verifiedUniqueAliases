{ pkgs ? import <nixpkgs> {}, binaryPath }:

let
  # Create the init script
  initScript = pkgs.writeScriptBin "init" ''
    #!${pkgs.bash}/bin/bash
    set -e
    
    export PATH=/bin
    
    # Mount essential filesystems
    mkdir -p /proc /sys /dev /run /tmp /var/tmp /var/lib/dhcpcd
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev || true
    
    # Network setup
    echo "Bringing up network..."
    ${pkgs.iproute2}/bin/ip link set lo up
    ${pkgs.iproute2}/bin/ip link set eth0 up
    ${pkgs.dhcpcd}/bin/dhcpcd eth0
    
    # Metadata fetcher
    fetch_metadata() {
        local key=$1
        ${pkgs.curl}/bin/curl -sf -H "Authorization: Bearer Oracle" \
            "http://169.254.169.254/opc/v1/instance/metadata/$key"
    }

    # Wait for metadata service
    echo "Waiting for metadata service..."
    for i in $(${pkgs.coreutils}/bin/seq 1 30); do
        if ${pkgs.curl}/bin/curl -sf http://169.254.169.254/ >/dev/null 2>&1; then
            break
        fi
        ${pkgs.coreutils}/bin/sleep 1
    done

    # Fetch environment variables
    export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
    export DOMAIN=$(fetch_metadata domain)
    export SECRET_OCID=$(fetch_metadata secret_ocid)
    export OCI_REGION=$(${pkgs.curl}/bin/curl -sf http://169.254.169.254/opc/v2/instance/region)
    export NOTIFICATION_TOPIC_ID=$(fetch_metadata notification_topic_id)

    echo "Starting PayPal Auth application..."
    exec /bin/paypal-auth-vm
  '';

in
{
  initramfs = pkgs.makeInitrd {
    contents = [
      # Init script
      { object = "${initScript}/bin/init"; symlink = "/init"; }
      
      # Application binary
      { object = binaryPath; symlink = "/bin/paypal-auth-vm"; }
      
      # Copy libraries for the binary
      # Note: makeInitrd will NOT automatically copy shared libraries
      # We need to copy them manually
    ] ++ (
      # Copy shared libraries needed by the binary
      let
        ldd = "${pkgs.glibc.bin}/bin/ldd";
        libs = builtins.filter (x: x != "") (
          pkgs.lib.splitString "\n" (
            builtins.readFile (
              pkgs.runCommand "get-libs" {} ''
                ${ldd} ${binaryPath} | ${pkgs.gawk}/bin/awk '{print $3}' | ${pkgs.gnugrep}/bin/grep '^/' > $out || true
              ''
            )
          )
        );
      in
        map (lib: { object = lib; symlink = "/lib/${baseNameOf lib}"; }) libs
    );
    
    compressor = "gzip -9";
  };
  
  kernel = pkgs.linux;
}
