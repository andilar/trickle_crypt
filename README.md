# trickle_crypt

`tricklecrypt` is a `no_std`, allocation-free record encryption library for
embedded systems. Instead of encrypting an unbounded message in one call, it
processes one size-limited, independently authenticated record at a time.

> **Security status:** This project is experimental and has not received an
> independent security audit. Do not use it to protect production data yet.

## Design

- XChaCha20-Poly1305 from the audited RustCrypto implementation
- one authentication tag per bounded-size record
- authenticated version, final-record marker, sequence number, and length
- strictly ordered decryption to reject missing, repeated, or reordered records
- caller-owned input and output buffers; no allocator required
- key material is non-cloneable, non-debuggable, and wiped on drop

The configured record size bounds the amount of cryptographic work performed by
one `encrypt_next` or `decrypt_next` call. It is a byte limit, not a real-time
deadline; measure the chosen size on the target hardware.

## Example

```rust
use tricklecrypt::{
    DecryptSession, EncryptSession, NoncePrefix, SecretKey, HEADER_SIZE, TAG_SIZE,
};

const MAX_RECORD: usize = 256;
let key = [7_u8; 32];
let prefix = NoncePrefix::new([9_u8; 16]);

let mut encrypted = [0_u8; MAX_RECORD + HEADER_SIZE + TAG_SIZE];
let mut encryptor = EncryptSession::new(SecretKey::new(key), prefix, MAX_RECORD)?;
let encrypted_progress = encryptor.encrypt_next(b"sensor data", &mut encrypted, true)?;

let mut plaintext = [0_u8; MAX_RECORD];
let mut decryptor = DecryptSession::new(SecretKey::new(key), prefix, MAX_RECORD)?;
let decrypted_progress = decryptor.decrypt_next(
    &encrypted[..encrypted_progress.written],
    &mut plaintext,
)?;

assert_eq!(&plaintext[..decrypted_progress.written], b"sensor data");
# Ok::<(), tricklecrypt::Error>(())
```

## Nonce requirement

`NoncePrefix` is public metadata, not a secret. It **must be unique for every
stream encrypted with the same key**. Store or transmit it alongside the
encrypted records. Generating and persisting prefixes is intentionally left to
the platform, because embedded random-number and storage facilities vary.

## Record format (version 1)

Each record consists of a 16-byte authenticated header, ciphertext, and a
16-byte authentication tag:

```text
magic (2) | version (1) | flags (1) | sequence (8) | length (4)
ciphertext (length) | authentication tag (16)
```

Multi-record messages must end with a record carrying the final flag. Plaintext
is returned only after its record has been authenticated.
