# To learn more about how to use Nix to configure your environment
# see: https://firebase.google.com/docs/studio/customize-workspace
{ pkgs, ... }: {
  # Which nixpkgs channel to use.
  # Channel: nixos-23.11
  # This provides reproducible builds with security updates
  channel = "nixos-25.05"; # or "unstable"

  # Use https://search.nixos.org/packages to find packages
  packages = [
    # Build tools
    pkgs.curl
    pkgs.gcc
    pkgs.gnumake
    pkgs.rustup
    
    # Dracut and kernel
    pkgs.xorriso  # Required for grub-mkrescue
    pkgs.linuxPackages.linux
    pkgs.kmod
    
    # Container support
    pkgs.podman
    pkgs.sudo
    
    # Archive tools
    pkgs.cpio
    pkgs.gzip
    pkgs.xz
    
    # QEMU and image creation tools
    pkgs.qemu_kvm      # Provides qemu-img for image conversion
    pkgs.grub2         # Bootloader installation
    pkgs.parted        # Disk partitioning
    pkgs.dosfstools    # FAT filesystem support
    pkgs.e2fsprogs     # ext4 filesystem tools (mkfs.ext4)
    pkgs.util-linux    # Loop device support (losetup, mount, etc.)
  ];

  # Sets environment variables in the workspace
  env = {};

  idx = {
    # Search for the extensions you want on https://open-vsx.org/ and use "publisher.id"
    extensions = [
      # "vscodevim.vim"
    ];

    # Enable previews
    previews = {
      enable = true;
      previews = {};
    };

    # Workspace lifecycle hooks
    workspace = {
      # Runs when a workspace is first created
      onCreate = {
        # Install add-determinism for reproducible builds
        # This tool normalizes binaries and archives to remove non-deterministic metadata
        install-add-determinism = "cargo install add-determinism || echo 'add-determinism installation skipped'";
      };
      # Runs when the workspace is (re)started
      onStart = {
        # Example: start a background task to watch and re-build backend code
        # watch-backend = "npm run watch-backend";
      };
    };
  };
}
