{
  # Enable Nix Flakes support and point to the flake in this directory.
  # This appears to be the correct syntax, and my previous error was
  # on a different line.
  nix.flakes.self.path = ".";

  # By enabling the flake above, Project IDX should automatically use the
  # `devShells.default` from our `flake.nix`. The explicit
  # `idx.workspace.devShell` line from my previous attempts was incorrect.

  # We can keep the other IDX-specific settings.
  idx.extensions = [ "rust-lang.rust-analyzer" ];
  idx.previews = { enable = true; };

  # Retain existing lifecycle hooks.
  idx.workspace.onCreate = {
    install-tools = "git lfs install && rustup default stable";
    fix-podman = "./fix-podman-idx.sh";
  };
  idx.workspace.onStart = {
    share-mount = "sudo mount --make-rshared /";
  };
}
