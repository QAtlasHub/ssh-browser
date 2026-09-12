//! Turn an SSH host into a real browser origin.

pub mod annot;
pub mod cache;
pub mod config;
pub mod control;
pub mod fs;
pub mod origin;
pub mod prefetch;
pub mod sftp;

#[cfg(test)]
mod testing;
