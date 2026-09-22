use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroize;

use crate::{
    record::{Header, HEADER_SIZE, RECORD_OVERHEAD},
    Error, NoncePrefix, SecretKey,
};

/// The amount of input consumed and output produced by one bounded operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordProgress {
    pub sequence: u64,
    pub consumed: usize,
    pub written: usize,
    pub final_record: bool,
}

/// Encrypts a stream as independently authenticated, bounded-size records.
pub struct EncryptSession {
    key: SecretKey,
    nonce_prefix: NoncePrefix,
    next_sequence: u64,
    max_record_size: usize,
    finished: bool,
}

impl EncryptSession {
    /// Creates a new stream beginning at sequence zero.
    ///
    /// `nonce_prefix` must be unique for every stream encrypted with `key`.
    pub fn new(
        key: SecretKey,
        nonce_prefix: NoncePrefix,
        max_record_size: usize,
    ) -> Result<Self, Error> {
        validate_max_record_size(max_record_size)?;
        Ok(Self {
            key,
            nonce_prefix,
            next_sequence: 0,
            max_record_size,
            finished: false,
        })
    }

    /// Encrypts one record. The operation is bounded by `max_record_size`.
    pub fn encrypt_next(
        &mut self,
        plaintext: &[u8],
        output: &mut [u8],
        final_record: bool,
    ) -> Result<RecordProgress, Error> {
        self.ensure_active()?;
        validate_payload(plaintext.len(), self.max_record_size, final_record)?;
        if self.next_sequence == u64::MAX && !final_record {
            return Err(Error::SequenceExhausted);
        }

        let required =
            RECORD_OVERHEAD
                .checked_add(plaintext.len())
                .ok_or(Error::RecordTooLarge {
                    len: plaintext.len(),
                    max: self.max_record_size,
                })?;
        ensure_output_capacity(output, required)?;

        let sequence = self.next_sequence;
        let header = Header {
            sequence,
            payload_len: plaintext.len(),
            final_record,
        }
        .encode();
        output[..HEADER_SIZE].copy_from_slice(&header);

        let payload_end = HEADER_SIZE + plaintext.len();
        output[HEADER_SIZE..payload_end].copy_from_slice(plaintext);

        let nonce_bytes = nonce(self.nonce_prefix, sequence);
        let tag = cipher(&self.key)
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce_bytes),
                &header,
                &mut output[HEADER_SIZE..payload_end],
            )
            .map_err(|_| Error::AuthenticationFailed)?;
        output[payload_end..required].copy_from_slice(&tag);

        self.advance(final_record);
        Ok(RecordProgress {
            sequence,
            consumed: plaintext.len(),
            written: required,
            final_record,
        })
    }

    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    fn ensure_active(&self) -> Result<(), Error> {
        if self.finished {
            Err(Error::AlreadyFinished)
        } else {
            Ok(())
        }
    }

    fn advance(&mut self, final_record: bool) {
        self.finished = final_record;
        if !final_record {
            self.next_sequence += 1;
        }
    }
}

/// Authenticates and decrypts a strictly ordered record stream.
pub struct DecryptSession {
    key: SecretKey,
    nonce_prefix: NoncePrefix,
    next_sequence: u64,
    max_record_size: usize,
    finished: bool,
}

impl DecryptSession {
    /// Creates a new stream beginning at sequence zero.
    pub fn new(
        key: SecretKey,
        nonce_prefix: NoncePrefix,
        max_record_size: usize,
    ) -> Result<Self, Error> {
        validate_max_record_size(max_record_size)?;
        Ok(Self {
            key,
            nonce_prefix,
            next_sequence: 0,
            max_record_size,
            finished: false,
        })
    }

    /// Authenticates and decrypts exactly one complete record.
    ///
    /// On authentication failure, the tentative plaintext in `output` is wiped.
    pub fn decrypt_next(
        &mut self,
        record: &[u8],
        output: &mut [u8],
    ) -> Result<RecordProgress, Error> {
        self.ensure_active()?;
        if record.len() < RECORD_OVERHEAD {
            return Err(Error::InputTooShort {
                minimum: RECORD_OVERHEAD,
                actual: record.len(),
            });
        }

        let header = Header::decode(&record[..HEADER_SIZE])?;
        validate_payload(
            header.payload_len,
            self.max_record_size,
            header.final_record,
        )?;
        if header.sequence != self.next_sequence {
            return Err(Error::UnexpectedSequence {
                expected: self.next_sequence,
                actual: header.sequence,
            });
        }
        if header.sequence == u64::MAX && !header.final_record {
            return Err(Error::SequenceExhausted);
        }

        let required = RECORD_OVERHEAD
            .checked_add(header.payload_len)
            .ok_or(Error::InvalidHeader)?;
        if record.len() != required {
            return Err(Error::InvalidHeader);
        }
        ensure_output_capacity(output, header.payload_len)?;

        let payload_end = HEADER_SIZE + header.payload_len;
        output[..header.payload_len].copy_from_slice(&record[HEADER_SIZE..payload_end]);

        let nonce_bytes = nonce(self.nonce_prefix, header.sequence);
        let tag = Tag::from_slice(&record[payload_end..required]);
        let result = cipher(&self.key).decrypt_in_place_detached(
            XNonce::from_slice(&nonce_bytes),
            &record[..HEADER_SIZE],
            &mut output[..header.payload_len],
            tag,
        );
        if result.is_err() {
            output[..header.payload_len].zeroize();
            return Err(Error::AuthenticationFailed);
        }

        self.advance(header.final_record);
        Ok(RecordProgress {
            sequence: header.sequence,
            consumed: required,
            written: header.payload_len,
            final_record: header.final_record,
        })
    }

    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    fn ensure_active(&self) -> Result<(), Error> {
        if self.finished {
            Err(Error::AlreadyFinished)
        } else {
            Ok(())
        }
    }

    fn advance(&mut self, final_record: bool) {
        self.finished = final_record;
        if !final_record {
            self.next_sequence += 1;
        }
    }
}

fn validate_max_record_size(max_record_size: usize) -> Result<(), Error> {
    if max_record_size == 0 || max_record_size > u32::MAX as usize {
        Err(Error::InvalidMaxRecordSize)
    } else {
        Ok(())
    }
}

fn validate_payload(len: usize, max: usize, final_record: bool) -> Result<(), Error> {
    if len == 0 && !final_record {
        return Err(Error::EmptyRecord);
    }
    if len > max || len > u32::MAX as usize {
        return Err(Error::RecordTooLarge { len, max });
    }
    Ok(())
}

fn ensure_output_capacity(output: &[u8], required: usize) -> Result<(), Error> {
    if output.len() < required {
        Err(Error::OutputTooSmall {
            required,
            available: output.len(),
        })
    } else {
        Ok(())
    }
}

fn cipher(key: &SecretKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()))
}

fn nonce(prefix: NoncePrefix, sequence: u64) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(prefix.as_bytes());
    nonce[16..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}
