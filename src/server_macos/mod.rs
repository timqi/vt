//! macOS-only server side: keychain, LocalAuthentication, FIDO2,
//! the SSH agent, and admin command bodies. The whole tree is gated
//! `#[cfg(target_os = "macos")]` from `main.rs`, so anything below this
//! point can assume macOS APIs are available.

pub mod admin;
pub mod audit;
pub mod authorization;
pub mod fido2;
pub mod fido2_cli;
pub mod security;
pub mod ssh_agent;
pub mod ssh_cli;
pub mod store;
