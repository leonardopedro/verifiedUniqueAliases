{ pkgs ? import <nixpkgs> {}
, binaryPath ? null
}:

let
  # Pre-built glibc binary from Docker build
  theBinary = if binaryPath != null then binaryPath
              else ./target/release/paypal-auth-vm;

in
  pkgs.dockerTools.buildLayeredImage {
    name = "eu.gcr.io/project-ae136ba1-3cc9-42cf-a48/paypal-rust-app";
    tag = "latest";
    
    contents = [
      pkgs.dockerTools.caCertificates
      pkgs.glibc
      pkgs.pkgsStatic.busybox
    ];
    
    config = {
      Entrypoint = [ "/bin/paypal-auth-vm" ];
      Env = [
        "PAYPAL_CLIENT_ID=***REMOVED***"
        "DOMAIN=auth.airma.de"
        "ORG_KEY_NAME=ORG_SIGNING_KEY"
        "PAYPAL_SECRET_NAME=PAYPAL_SECRET"
        "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
      ];
      ExposedPorts = {
        "80/tcp" = {};
        "443/tcp" = {};
      };
      Labels = {
        "tee.launch-policy.allow_log_redirect" = "always";
        "tee.launch-policy.allow_cmd_override" = "false";
      };
    };
    
    extraCommands = ''
      mkdir -p bin
      cp ${theBinary} bin/paypal-auth-vm
      chmod +x bin/paypal-auth-vm
    '';
  }
