{ pkgs ? import <nixpkgs> {}, binaryPath }:

let
  # Define a minimal NixOS configuration to generate the initrd
  config = (pkgs.lib.evalModules {
    modules = [
      ({ config, pkgs, ... }: {
        # Use the same package set
        nixpkgs.pkgs = pkgs;

        # Minimal initrd configuration
        boot.initrd = {
          enable = true;
          
          # We don't need systemd in initrd for this simple use case, 
          # but the standard initrd builder is flexible.
          # We will use 'extraUtilsCommands' to install our binary and its libs.
          
          extraUtilsCommands = ''
            # Copy the binary
            cp ${binaryPath} $out/bin/paypal-auth-vm
            
            # Use copy_bin_and_libs to copy shared libraries (glibc, etc.)
            # This function is provided by the initrd builder environment
            copy_bin_and_libs $out/bin/paypal-auth-vm
          '';

          # Custom init script
          # We replace the default init with our own script
          preLVMCommands = ''
            # Basic network setup (using standard tools included in extraUtils)
            echo "Bringing up network..."
            ip link set lo up
            ip link set eth0 up
            
            # DHCP
            # We need to make sure dhcpcd is available. 
            # It's usually not in the minimal initrd unless added.
            # But we can add it to extraUtilsCommands if needed, 
            # or use busybox udhcpc if we kept busybox.
            # Since user didn't want busybox, we rely on what we have.
            # Let's add dhcpcd to extraUtilsCommands below.
            
            dhcpcd eth0
            
            # Metadata fetcher
            fetch_metadata() {
                local key=$1
                curl -sf -H "Authorization: Bearer Oracle" \
                    "http://169.254.169.254/opc/v1/instance/metadata/$key"
            }

            # Wait for metadata service
            echo "Waiting for metadata service..."
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
            exec paypal-auth-vm
          '';
        };
        
        # Add necessary tools to the initrd
        boot.initrd.extraUtilsCommandsTest = ''
          $out/bin/curl --version
          $out/bin/dhcpcd --version
        '';
        
        # We need to explicitly add tools to extraUtilsCommands
        boot.initrd.extraUtilsCommands = pkgs.lib.mkAfter ''
          # Add curl
          cp ${pkgs.curl}/bin/curl $out/bin/curl
          copy_bin_and_libs $out/bin/curl
          
          # Add dhcpcd
          cp ${pkgs.dhcpcd}/bin/dhcpcd $out/bin/dhcpcd
          copy_bin_and_libs $out/bin/dhcpcd
          
          # Add basic tools (ip, etc are usually there, but let's be safe)
          # The standard initrd has busybox or minimal tools. 
          # If we want to avoid busybox, we should ensure we have what we need.
          # But 'copy_bin_and_libs' is the key.
        '';
      })
      
      # Import the standard NixOS initrd module
      <nixpkgs/nixos/modules/system/boot/initrd.nix>
      <nixpkgs/nixos/modules/system/boot/kernel.nix>
      <nixpkgs/nixos/modules/misc/nixpkgs.nix>
      <nixpkgs/nixos/modules/system/etc/etc.nix>
    ];
  });

in
{
  # The initrd derivation
  initramfs = config.config.system.build.initialRamdisk;
  
  # The kernel
  kernel = config.config.boot.kernelPackages.kernel;
}
