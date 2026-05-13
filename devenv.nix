{ pkgs, lib, ... }:

{
  packages = with pkgs; [
    openssl
    pkg-config
    libiconv
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" ];
  };

  env = {
    RUST_LOG = "debug";
    RUST_BACKTRACE = "1";
  } // lib.optionalAttrs pkgs.stdenv.isDarwin {
    # /opt/local/bin/ar (MacPorts) shadows a working ar on this host and breaks
    # cc-rs invocations for native crates (aws-lc-sys, ring, rusqlite/bundled).
    AR = "${pkgs.cctools}/bin/ar";
  };

  pre-commit.hooks = {
    clippy.enable = true;
    rustfmt.enable = true;
  };

  scripts = {
    dev.exec = "cargo run";
    check.exec = "cargo clippy -- -D warnings && cargo fmt --check";
    t.exec = "cargo test";
  };
}
