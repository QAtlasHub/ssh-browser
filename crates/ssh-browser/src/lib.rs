//! Turn an SSH host into a real browser origin.

pub mod annot;
pub mod cache;
pub mod control;
pub mod fs;
pub mod origin;
pub mod sftp;

#[cfg(test)]
mod testing;
