//! Settings: built-in profiles, the system and user config files, and how
//! they combine into a per-source-class policy.

pub mod file;
pub mod load;
pub mod model;
pub mod resolve;

#[expect(unused_imports, reason = "wired into the CLI in Task 9")]
pub use load::Settings;
