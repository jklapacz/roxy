use clap::Parser;
use roxy_proxy_lib::cli::{CaAction, Cli, Command};
use roxy_proxy_lib::{ca_cmd, serve};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cmd = cli.command.unwrap_or(Command::Serve { fingerprint: None });
    match cmd {
        Command::Serve { fingerprint } => {
            serve::run(cli.config.as_deref(), fingerprint.as_deref()).await
        }
        Command::Ca { action } => match action {
            CaAction::Install { ca_dir, print_only } => ca_cmd::install(ca_dir, print_only),
            CaAction::Uninstall { ca_dir, print_only } => ca_cmd::uninstall(ca_dir, print_only),
        },
    }
}
