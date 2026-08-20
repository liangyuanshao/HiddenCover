//! HiddenCover research prototype.
//!
//! This crate is intentionally compact and unaudited.  It exists to test the
//! protocol construction and to obtain reproducible performance measurements.

pub mod credential;
pub mod oom;
pub mod protocol;
pub mod tree;

pub use protocol::{Credential, HiddenCover, Presentation, RevocationState, ShowBreakdown};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid tree size or node index")]
    InvalidTree,
    #[error("no unused credential leaf remains")]
    CapacityExhausted,
    #[error("unknown or already revoked serial number")]
    UnknownCredential,
    #[error("credential is revoked under the supplied state")]
    Revoked,
    #[error("stale or unauthenticated revocation state")]
    InvalidState,
    #[error("presentation nonce has already been accepted")]
    Replay,
    #[error("malformed proof statement")]
    MalformedProof,
    #[error("cryptographic verification failed")]
    Verification,
}

pub type Result<T> = core::result::Result<T, Error>;
