//! s3vault on-disk and on-wire formats.
//!
//! * [`keyring`]: the master keyring (text file, held by the key service) and the subkeys derived from it.
//! * [`object`]: the encrypted object format stored in the store of record (preamble, sealed header,
//!   64 KiB AEAD body chunks) and the keyed-hash object names.
//! * [`spool`]: the same chunk cipher for local temporary files (upload spools, multipart staging).
//! * [`keyproto`]: the mutual-PSK protocol between the key service and the proxy.
//!
//! This crate has no async runtime and no C dependencies, so it also builds the static key-service binary.

pub mod hpke;
pub mod keyproto;
pub mod keyring;
pub mod keys2;
pub mod keystore;
pub mod ledger;
pub mod object;
pub mod slots;
pub mod spool;

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("unknown key id {0}")]
    UnknownKid(u32),
    #[error("authentication failed (tampered, truncated, swapped or wrong key)")]
    Auth,
    #[error("keyring: {0}")]
    Keyring(String),
}

pub type Result<T> = std::result::Result<T, FormatError>;
