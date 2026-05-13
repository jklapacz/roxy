mod ca_cmd;
mod cli;
#[allow(dead_code)]
mod handler;
mod serve;

use clap::Parser;
use cli::{CaAction, Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cmd = cli.command.unwrap_or(Command::Serve);
    match cmd {
        Command::Serve => serve::run(cli.config.as_deref()).await,
        Command::Ca { action } => match action {
            CaAction::Install { ca_dir, print_only } => ca_cmd::install(ca_dir, print_only),
            CaAction::Uninstall { ca_dir, print_only } => ca_cmd::uninstall(ca_dir, print_only),
        },
    }
}
