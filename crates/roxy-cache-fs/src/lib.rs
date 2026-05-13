#![cfg_attr(test, allow(clippy::unwrap_used))]

mod blob;
mod index;
mod writer;

pub use writer::FsCache;
