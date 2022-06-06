with import <nixpkgs> {};
mkShell {
  nativeBuildInputs = [ rustc cargo ];
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
