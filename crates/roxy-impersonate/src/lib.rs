#![cfg_attr(test, allow(clippy::unwrap_used))]

mod error;
mod profile;

pub use error::ImpersonateError;
pub use profile::{Profile, ProfileName, ProfileNameError, DEFAULT_LABEL, NONE_LABEL};
