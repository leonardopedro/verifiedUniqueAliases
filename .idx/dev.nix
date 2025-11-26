# To learn more about how to use Nix to configure your environment
# see: https://firebase.google.com/docs/studio/customize-workspace
{ pkgs, ... }: {
  # Which nixpkgs channel to use.
  channel = "stable-24.05"; # or "unstable"

  # Use https://search.nixos.org/packages to find packages
  packages = [
    # pkgs.go
    #pkgs.python311
    #pkgs.python311Packages.pip
    # pkgs.nodejs_20
    # pkgs.nodePackages.nodemon
    pkgs.curl
    pkgs.gcc
    pkgs.gnumake
    pkgs.rustup
    pkgs.dracut
    pkgs.linux
    pkgs.musl
    pkgs.musl.dev
    pkgs.pkgsMusl.stdenv.cc
    pkgs.docker
    pkgs.docker-compose
  ];

  # Sets environment variables in the workspace
  env = { # Tell Cargo to use 'musl-gcc' for the musl target instead of guessing
    CC_x86_64_unknown_linux_musl = "musl-gcc";
    CXX_x86_64_unknown_linux_musl = "musl-g++";
    
    # Linker configuration
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "musl-gcc";
    
    # Optional: Archive tool
    AR_x86_64_unknown_linux_musl = "ar";
    };

  services.docker.enable = true;

  idx = {
    # Search for the extensions you want on https://open-vsx.org/ and use "publisher.id"
    extensions = [
      # "vscodevim.vim"
    ];

    # Enable previews
    previews = {
      enable = true;
      previews = {
        # web = {
        #   # Example: run "npm run dev" with PORT set to IDX's defined port for previews,
        #   # and show it in IDX's web preview panel
        #   command = ["npm" "run" "dev"];
        #   manager = "web";
        #   env = {
        #     # Environment variables to set for your server
        #     PORT = "$PORT";
        #   };
        # };
      };
    };

    # Workspace lifecycle hooks
    workspace = {
      # Runs when a workspace is first created
      onCreate = {
        # Example: install JS dependencies from NPM
        # npm-install = "npm install";
      };
      # Runs when the workspace is (re)started
      onStart = {
        # Example: start a background task to watch and re-build backend code
        # watch-backend = "npm run watch-backend";
      };
    };
  };
}
