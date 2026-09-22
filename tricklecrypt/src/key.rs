use zeroize::Zeroize;

use crate::record::{KEY_SIZE, NONCE_PREFIX_SIZE};

/// An owned encryption key which is wiped when dropped.
///
/// The type deliberately implements neither `Clone` nor `Debug`.
pub struct SecretKey([u8; KEY_SIZE]);

impl SecretKey {
    pub const fn new(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The non-secret, per-stream part of every record nonce.
///
/// A prefix must never be reused with the same key. The session appends the
/// monotonically increasing record sequence to form a 24-byte XChaCha nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoncePrefix([u8; NONCE_PREFIX_SIZE]);

impl NoncePrefix {
    pub const fn new(bytes: [u8; NONCE_PREFIX_SIZE]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; NONCE_PREFIX_SIZE] {
        &self.0
    }
}
