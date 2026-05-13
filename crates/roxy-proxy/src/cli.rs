use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "roxy", version, about = "Caching MITM proxy")]
pub struct Cli {
    /// Path to roxy config TOML.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy.
    Serve,
    /// CA trust-store management.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum CaAction {
    /// Install the generated CA into the host trust store.
    Install {
        /// Override the CA directory.
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        /// Print the platform command instead of executing it.
        #[arg(long)]
        print_only: bool,
    },
    /// Remove the installed CA from the host trust store.
    Uninstall {
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        #[arg(long)]
        print_only: bool,
    },
}
