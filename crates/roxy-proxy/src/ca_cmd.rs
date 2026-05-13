use std::path::PathBuf;

pub fn install(_ca_dir: Option<PathBuf>, _print_only: bool) -> anyhow::Result<()> {
    anyhow::bail!("ca install not yet wired - see Task 22")
}

pub fn uninstall(_ca_dir: Option<PathBuf>, _print_only: bool) -> anyhow::Result<()> {
    anyhow::bail!("ca uninstall not yet wired - see Task 22")
}
