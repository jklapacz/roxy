//! Profile = a named browser fingerprint. Builtins map to `wreq_util::Emulation`
//! variants; customs come from TOML files (loader lands in Task 5).

use std::sync::Arc;

/// Reserved label for the rustls path. Cannot collide with a user profile
/// because it starts with `_` and user names must match `[a-z0-9][a-z0-9-]*`.
pub const DEFAULT_LABEL: &str = "_default";

/// Header value that forces the rustls path even if a global default is set.
pub const NONE_LABEL: &str = "none";

/// A canonical, kebab-case profile name. Constructed via [`ProfileName::parse`]
/// which enforces `^[a-z0-9][a-z0-9-]*$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileName(Arc<str>);

impl ProfileName {
    pub fn parse(s: &str) -> Result<Self, ProfileNameError> {
        if s.is_empty() {
            return Err(ProfileNameError::Empty);
        }
        let first = s.as_bytes()[0];
        if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            return Err(ProfileNameError::BadStart);
        }
        for &b in s.as_bytes() {
            let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
            if !ok {
                return Err(ProfileNameError::BadChar(b as char));
            }
        }
        Ok(Self(Arc::from(s)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProfileNameError {
    #[error("profile name is empty")]
    Empty,
    #[error("profile name must start with [a-z0-9]")]
    BadStart,
    #[error("profile name contains invalid character: {0:?}")]
    BadChar(char),
}

/// Builtin profiles. Each maps to a `wreq_util::Emulation` variant. Adding a
/// new wreq variant is a one-line addition here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    Chrome137,
    Firefox139,
    Safari18_3_1,
    Edge134,
    OkHttp5,
}

impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Profile::Chrome137 => "chrome-137",
            Profile::Firefox139 => "firefox-139",
            Profile::Safari18_3_1 => "safari-18-3-1",
            Profile::Edge134 => "edge-134",
            Profile::OkHttp5 => "okhttp-5",
        }
    }

    pub fn all() -> &'static [Profile] {
        &[
            Profile::Chrome137,
            Profile::Firefox139,
            Profile::Safari18_3_1,
            Profile::Edge134,
            Profile::OkHttp5,
        ]
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::all().iter().copied().find(|p| p.name() == s)
    }

    /// Returns the underlying wreq_util Emulation variant.
    pub fn emulation(self) -> wreq_util::Emulation {
        match self {
            Profile::Chrome137 => wreq_util::Emulation::Chrome137,
            Profile::Firefox139 => wreq_util::Emulation::Firefox139,
            Profile::Safari18_3_1 => wreq_util::Emulation::Safari18_3_1,
            Profile::Edge134 => wreq_util::Emulation::Edge134,
            Profile::OkHttp5 => wreq_util::Emulation::OkHttp5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name_accepts_kebab_case() {
        assert!(ProfileName::parse("chrome-137").is_ok());
        assert!(ProfileName::parse("a").is_ok());
        assert!(ProfileName::parse("safari-18-3-1").is_ok());
    }

    #[test]
    fn profile_name_rejects_underscore_and_upper_and_space() {
        assert_eq!(
            ProfileName::parse("Chrome137"),
            Err(ProfileNameError::BadStart)
        );
        assert_eq!(
            ProfileName::parse("chrome_137"),
            Err(ProfileNameError::BadChar('_'))
        );
        assert_eq!(
            ProfileName::parse("chrome 137"),
            Err(ProfileNameError::BadChar(' '))
        );
        assert_eq!(ProfileName::parse(""), Err(ProfileNameError::Empty));
        assert_eq!(ProfileName::parse("-foo"), Err(ProfileNameError::BadStart));
    }

    #[test]
    fn every_builtin_resolves_round_trip() {
        for p in Profile::all() {
            let name = p.name();
            assert_eq!(Profile::from_name(name), Some(*p));
            ProfileName::parse(name).unwrap_or_else(|e| panic!("bad name {name}: {e:?}"));
        }
    }

    #[test]
    fn unknown_builtin_returns_none() {
        assert_eq!(Profile::from_name("chrome-999"), None);
    }

    #[test]
    fn default_label_is_reserved() {
        // The validation regex starts with [a-z0-9], so `_default` is
        // unparseable as a user profile name. That guarantees no collision.
        assert!(ProfileName::parse(DEFAULT_LABEL).is_err());
    }
}
