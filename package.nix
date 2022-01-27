{ sources ? import ./nix/sources.nix }:
let
  inherit ((import ./nix) sources) naersk;
in
naersk.buildPackage ./.
