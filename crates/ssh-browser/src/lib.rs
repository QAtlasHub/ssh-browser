//! Turn an SSH host into a real browser origin.

pub mod cache;
pub mod config;
pub mod control;
pub mod fs;
pub mod origin;
pub mod prefetch;
pub mod sftp;
pub mod ssh_config;
pub mod theme;

#[cfg(test)]
mod testing;
