#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! Standalone TLS-fingerprint capture server.
//!
//! Roxy *emulates* browser fingerprints from custom-profile TOML files; this
//! crate makes those files easy to produce. It runs a dedicated TLS server on
//! its own port: a browser configured to trust roxy's CA visits
//! `https://<host>:<port>/?name=<profile-name>` and roxy captures that client's
//! real TLS ClientHello and HTTP/2 settings, renders a `roxy-impersonate`
//! custom-profile TOML, writes it to the profiles directory, and echoes it back
//! in the response for review.
//!
//! Running on its own port (rather than inside the proxy's CONNECT pipeline)
//! lets the server own the connection end to end, which is what makes the
//! raw-bytes work — peeking the ClientHello, teeing the HTTP/2 frames —
//! straightforward.

mod client_hello;
mod h2;
mod profile;
mod server;
mod stream;

pub use server::run;
