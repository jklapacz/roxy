use super::{Plan, TrustError};
use crate::ca::Ca;
use std::process::Command;

const SYSTEM_DIR: &str = "/usr/local/share/ca-certificates";

pub fn install(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    let target = format!("{SYSTEM_DIR}/roxy-ca.crt");
    if std::path::Path::new(&target).exists() {
        return Ok(Plan::AlreadyInstalled);
    }
    let cmd = vec![
        "install".into(),
        "-m".into(),
        "0644".into(),
        ca.cert_path.display().to_string(),
        target.clone(),
    ];
    let update = vec!["update-ca-certificates".into()];

    if print_only || !is_root() {
        let mut plan = cmd.clone();
        plan.extend(update.clone());
        if print_only {
            return Ok(Plan::PrintOnly(plan));
        } else {
            let pretty = format!("sudo {}", plan.join(" "));
            return Err(TrustError::NeedsRoot(pretty));
        }
    }

    let status = Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    if !status.success() {
        return Err(TrustError::Command(format!("install exited {status}")));
    }
    let status = Command::new(&update[0]).args(&update[1..]).status()?;
    if !status.success() {
        return Err(TrustError::Command(format!(
            "update-ca-certificates exited {status}"
        )));
    }
    Ok(Plan::Execute(cmd))
}

pub fn uninstall(_ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    let target = format!("{SYSTEM_DIR}/roxy-ca.crt");
    let exists = std::path::Path::new(&target).exists();
    if !exists {
        return Ok(Plan::AlreadyInstalled);
    }
    let cmd = vec!["rm".into(), "-f".into(), target.clone()];
    let update = vec!["update-ca-certificates".into()];

    if print_only || !is_root() {
        let mut plan = cmd.clone();
        plan.extend(update.clone());
        if print_only {
            return Ok(Plan::PrintOnly(plan));
        } else {
            let pretty = format!("sudo {}", plan.join(" "));
            return Err(TrustError::NeedsRoot(pretty));
        }
    }
    Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    Command::new(&update[0]).args(&update[1..]).status()?;
    Ok(Plan::Execute(cmd))
}

fn is_root() -> bool {
    #[cfg(unix)]
    return rustix::process::geteuid().is_root();
    #[cfg(not(unix))]
    return false;
}
