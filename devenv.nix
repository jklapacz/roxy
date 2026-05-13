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
