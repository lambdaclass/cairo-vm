with import <nixpkgs> {};
mkShell {
  nativeBuildInputs = [ libiconv rustc cargo ];
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
  shellHook =
  ''
  cargo build
  exit
  '';
}
