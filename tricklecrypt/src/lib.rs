#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../../README.md")]

mod error;
mod key;
mod record;
mod session;

pub use error::Error;
pub use key::{NoncePrefix, SecretKey};
pub use record::{HEADER_SIZE, KEY_SIZE, NONCE_PREFIX_SIZE, TAG_SIZE};
pub use session::{DecryptSession, EncryptSession, RecordProgress};
