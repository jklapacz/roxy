#![cfg_attr(test, allow(clippy::unwrap_used))]

mod body;
mod client;
mod custom;
mod error;
mod profile;

pub use body::ImpersonateBody;
pub use client::ImpersonateClient;
pub use custom::{CustomProfile, CustomProfileSpec, Http2Spec, TlsSpec};
pub use error::ImpersonateError;
pub use profile::{Profile, ProfileName, ProfileNameError, DEFAULT_LABEL, NONE_LABEL};
