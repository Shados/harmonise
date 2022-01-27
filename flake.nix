{
  description = "An example Rust-project Nix Flake";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    naersk.url = "github:nmattia/naersk";
  };

  outputs = { self, flake-utils, nixpkgs, rust-overlay, naersk }: let
    # supportedSystems = [ "x86_64-linux" ]; # Example of explicit configuration of supported systems
    supportedSystems = flake-utils.lib.defaultSystems;
    # NOTE: Building with musl requires a .cargo/config.toml with the following:
    # [target.x86_64-unknown-linux-musl]
    # rustflags = [ "-C", "linker=ld.lld", "-C", "linker-flavor=ld.lld" ]
    # FIXME: Eventually make this part of the Nix environment setup once rust-lang/cargo PR #7894 is merged
    # TODO: Look into using sccache as well, once the above is fixed?

    muslTarget = "x86_64-unknown-linux-musl";
    extraRustTargets = lib.singleton muslTarget;

    # Nix machinery
    lib = import "${nixpkgs}/lib";
    pkgs_ = lib.genAttrs supportedSystems (sys: pkgsFor nixpkgs sys);
    pkgsFor = pkgs: system: import pkgs {
      inherit system;
      overlays = [ (import rust-overlay) ];
    };
  in flake-utils.lib.eachSystem supportedSystems (system: let
    rustNativeBuildInputs = with pkgs; [
      lld openssl
    ];
    channel = "nightly";
    version = "2019-11-01";
    pkgs = pkgs_.${system};
    rustProfile = rustPkgs.default.override {
      extensions = [
        "clippy-preview"
        "rls-preview"
        "rustfmt-preview"
        "rust-src" # for go-to-def, completion, etc.
      ];
      targets = extraRustTargets;
    };
    minimalRustProfile = rustPkgs.minimal.override {
      targets = extraRustTargets;
    };
    rustPkgs = pkgs.rust-bin.${channel}.${version};
    buildTarget = pkgs.stdenv.targetPlatform.config;
    naersk-lib = naersk.lib."${system}".override {
      cargo = minimalRustProfile;
      rustc = minimalRustProfile;
    };
    mkDocHelper = name: let # {{{
      scriptName = "rust-doc" + (if builtins.stringLength name > 0 then "-${name}" else "");
      htmlPath = "${rustPkgs.rust-docs}/share/doc/rust/html/" +
        (if builtins.stringLength name > 0 then "${name}/" else "") + "index.html";
    in pkgs.buildPackages.writeScriptBin scriptName ''
      #!${pkgs.buildPackages.bash}/bin/bash
      browser="$(
        IFS=: ; for b in $BROWSER; do
          [ -n "$(type -P "$b" || true)" ] && echo "$b" && break
        done
      )"
      if [ -z "$browser" ]; then
        browser="$(type -P xdg-open || true)"
        if [ -z "$browser" ]; then
          browser="$(type -P w3m || true)"
          if [ -z "$browser" ]; then
            echo "$0: unable to start a web browser; please set \$BROWSER"
            exit 1
          fi
        fi
      fi
      exec "$browser" ${htmlPath}
    ''; # }}}
  in rec {
    # Shell configuration
    devShell = pkgs.mkShell {
      allowSubstitutes = false;
      preferLocalBuild = true;

      nativeBuildInputs = rustNativeBuildInputs ++ (with pkgs; [
        # Environment management
        niv

        # Build tools & native deps
        pkgconfig
      ]) ++ ([
        rustProfile
        (mkDocHelper "")
        (mkDocHelper "std")
        (mkDocHelper "book")
      ]);

      shellHook = ''
        # Un-break SSL
        unset SSL_CERT_FILE
        unset NIX_SSL_CERT_FILE

        # Per-toolchain cargo download caching etc.
        export CARGO_HOME=$HOME/.cargo/${channel}-${version}

        # Enable use of Cargo-provided binaries
        export PATH="$CARGO_HOME/bin:$PATH"

        # Per-project build artifacts
        PROJ_ID=$(echo '${toString ./.}' | sha256sum | cut -f 1 -d' ')
        PROJ_NAME=''${PWD##*/}
        export CARGO_TARGET_DIR="$HOME/.cargo/target/$PROJ_NAME-$PROJ_ID";
        unset PROJ_ID
      '';
      CARGO_BUILD_TARGET = [ buildTarget ];
    };

    # Chuck any other outputs wanted here
    # `nix build` support
    packages.harmonise = naersk-lib.buildPackage {
      pname = "harmonise";
      root = ./.;
      nativeBuildInputs = rustNativeBuildInputs;
      CARGO_BUILD_TARGET = muslTarget;
    };
    defaultPackage = packages.harmonise;
    # `nix run` support
    apps.harmonise = flake-utils.lib.mkApp {
      drv = packages.harmonise;
    };
    defaultApp = apps.harmonise;
  });
}
