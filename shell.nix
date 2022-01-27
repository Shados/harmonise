{ sources ? import ./nix/sources.nix }:
let
  inherit ((import ./nix) sources) pkgs rustSpec rustPkgs buildTarget extraRustTargets mkDocHelper;
in
pkgs.mkShell {
  allowSubstitutes = false;
  preferLocalBuild = true;

  nativeBuildInputs = (with pkgs; [
    # Environment management
    niv

    # Build tools & native deps
    lld
    pkgconfig
    openssl
  ]) ++ (with rustPkgs; [
    (rust.override {
      extensions = [
        "clippy-preview"
        "rls-preview"
        "rustfmt-preview"
        "rust-src" # for go-to-def, completion, etc.
      ];
      targets = [ buildTarget ] ++ extraRustTargets;
    })
    (mkDocHelper "")
    (mkDocHelper "std")
    (mkDocHelper "book")
  ]);

  shellHook = ''
    # Enable use of Cargo-provided binaries
    export PATH="$CARGO_HOME/bin:$PATH"

    # Un-break SSL
    unset SSL_CERT_FILE
    unset NIX_SSL_CERT_FILE

    # Per-toolchain cargo download caching etc.
    export CARGO_HOME=${with rustSpec; if rustSpec ? date
      then "${builtins.getEnv "HOME"}/.cargo/${date}-${channel}"
      else "${builtins.getEnv "HOME"}/.cargo/${channel}"}

    # Per-project build artifacts
    PROJ_PATH='${toString ./.}'
    PROJ_ID=$(echo "$PROJ_PATH" | sha256sum | cut -f 1 -d' ')
    PROJ_NAME=''${PROJ_PATH##*/}
    export CARGO_TARGET_DIR="${builtins.getEnv "HOME"}/.cargo/target/$PROJ_NAME-$PROJ_ID";
    unset PROJ_ID
  '';
  CARGO_BUILD_TARGET = [ buildTarget ];
}
