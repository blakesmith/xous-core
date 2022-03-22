{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/release-21.11.tar.gz") {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.flatbuffers
  ];
}
