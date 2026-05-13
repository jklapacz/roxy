use super::{Plan, TrustError};
use crate::ca::Ca;
use std::process::Command;

pub fn install(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    if installed(ca)? {
        return Ok(Plan::AlreadyInstalled);
    }
    let cmd = vec![
        "security".into(),
        "add-trusted-cert".into(),
        "-r".into(),
        "trustRoot".into(),
        "-k".into(),
        login_keychain(),
        ca.cert_path.display().to_string(),
    ];
    if print_only {
        return Ok(Plan::PrintOnly(cmd));
    }
    let status = Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    if !status.success() {
        return Err(TrustError::Command(format!("security exited {status}")));
    }
    Ok(Plan::Execute(cmd))
}

pub fn uninstall(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    if !installed(ca)? {
        return Ok(Plan::AlreadyInstalled); // semantically "nothing to do"
    }
    let cmd = vec![
        "security".into(),
        "delete-certificate".into(),
        "-c".into(),
        "Roxy Local CA".into(),
        login_keychain(),
    ];
    if print_only {
        return Ok(Plan::PrintOnly(cmd));
    }
    let _ = Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    Ok(Plan::Execute(cmd))
}

fn login_keychain() -> String {
    if let Some(home) = dirs::home_dir() {
        return home
            .join("Library/Keychains/login.keychain-db")
            .display()
            .to_string();
    }
    "login.keychain-db".into()
}

fn installed(_ca: &Ca) -> Result<bool, TrustError> {
    let out = Command::new("security")
        .args(["find-certificate", "-c", "Roxy Local CA", &login_keychain()])
        .output()?;
    // (matching by fingerprint requires DER export; CN is sufficient for MVP)
    Ok(out.status.success())
}
