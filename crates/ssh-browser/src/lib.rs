//! Turn an SSH host into a real browser origin.

pub mod cache;
pub mod fs;
pub mod origin;
pub mod sftp;

#[cfg(test)]
mod testing;
