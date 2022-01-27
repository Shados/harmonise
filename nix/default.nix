sources:
rec {
  extraRustTargets = [ "x86_64-unknown-linux-musl" ];
  # NOTE: Building with musl requires a .cargo/config.toml with the following:
  # [target.x86_64-unknown-linux-musl]
  # rustflags = [ "-C", "linker=ld.lld", "-C", "linker-flavor=ld.lld" ]
  # FIXME: Eventually make this part of the Nix environment setup once https://github.com/rust-lang/cargo/pull/7894 is merged
  # TODO: Look into using sccache as well, once the above is fixed?

  pkgs = import sources.nixpkgs {
    overlays = [
      (import sources.mozilla)
    ];
  };

  # Read Rust manifest from Niv pin
  rustSpec = let
      json = (builtins.fromJSON (builtins.readFile ./sources.json));
    in { inherit (json.rust-manifest) date channel sha256; };

  rustPkgs = pkgs.buildPackages.rustChannelOf rustSpec;
  buildTarget = pkgs.stdenv.targetPlatform.config;
  naersk = pkgs.callPackage sources.naersk { };

  mkDocHelper = name: let
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
  '';
}
