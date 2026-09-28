//! The review engine: plans chunked AI requests for the files a review
//! queued, answers them from the verdict cache where it can, and keeps the
//! approved baselines of user-level sources
//! (docs/superpowers/specs/2026-09-28-review-engine-design.md).

pub mod diff;
pub mod plan;
