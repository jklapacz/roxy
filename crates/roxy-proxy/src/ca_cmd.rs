use anyhow::Context;
use roxy_config::Config;
use roxy_mitm::trust::{install as t_install, uninstall as t_uninstall, Plan};
use roxy_mitm::Ca;
use std::path::{Path, PathBuf};

fn resolve_ca_dir(override_dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(d) = override_dir {
        return Ok(d);
    }
    let cfg = Config::default().with_expanded_paths()?;
    Ok(cfg.ca.dir)
}

fn load_ca(ca_dir: &Path) -> anyhow::Result<Ca> {
    Ca::load_or_create(ca_dir).context("CA load/create")
}

pub fn install(ca_dir: Option<PathBuf>, print_only: bool) -> anyhow::Result<()> {
    let ca_dir = resolve_ca_dir(ca_dir)?;
    let ca = load_ca(&ca_dir)?;
    match t_install(&ca, print_only)? {
        Plan::AlreadyInstalled => {
            println!("CA already installed.");
        }
        Plan::PrintOnly(cmd) => {
            println!("Would run:\n  {}", cmd.join(" "));
        }
        Plan::Execute(cmd) => {
            println!("Installed CA. Ran: {}", cmd.join(" "));
        }
    }
    Ok(())
}

pub fn uninstall(ca_dir: Option<PathBuf>, print_only: bool) -> anyhow::Result<()> {
    let ca_dir = resolve_ca_dir(ca_dir)?;
    let ca = load_ca(&ca_dir)?;
    match t_uninstall(&ca, print_only)? {
        Plan::AlreadyInstalled => {
            println!("CA not currently installed.");
        }
        Plan::PrintOnly(cmd) => {
            println!("Would run:\n  {}", cmd.join(" "));
        }
        Plan::Execute(cmd) => {
            println!("Uninstalled CA. Ran: {}", cmd.join(" "));
        }
    }
    Ok(())
}
