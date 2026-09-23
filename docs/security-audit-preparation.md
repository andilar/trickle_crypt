# Security audit preparation

This document defines the proposed scope and review checklist for an independent
security audit of `tricklecrypt` version 0.1.0. It is preparation material, not
an audit report or a claim of security.

## Audit objective

Determine whether an attacker who can create, delete, modify, replay, truncate,
or reorder records can cause unauthenticated plaintext to be accepted, violate
record ordering or stream-finality guarantees, reuse a nonce internally, expose
key material through the public API, or force work beyond the configured record
bound.

The review should also assess whether the API makes security-critical caller
obligations sufficiently difficult to misuse.

## In-scope code and dependencies

At the audit commit, record the exact Git commit and Rust toolchain. Review:

- `tricklecrypt/src/record.rs`: wire-format encoding and parsing;
- `tricklecrypt/src/session.rs`: nonce construction, authenticated data,
  encryption/decryption, state transitions, bounds, and failure behavior;
- `tricklecrypt/src/key.rs`: ownership and zeroization of key material;
- `tricklecrypt/src/error.rs` and the public exports in `src/lib.rs`;
- integration tests, CI configuration, Cargo manifest, and resolved dependency
  graph; and
- the relevant implementation and feature configuration of `chacha20poly1305`
  and `zeroize`.

Build scripts, unsafe project code, persistence, transport framing, random-number
generation, key provisioning, and application-level storage are absent from the
repository. Confirm that they remain absent; assess their documented trust
boundaries rather than treating them as implemented controls.

## Protocol summary

Each record is:

```text
header = "TC" || version:u8 || flags:u8 || sequence:u64be || length:u32be
nonce  = nonce_prefix:16-bytes || sequence:u64be
body   = XChaCha20-Poly1305(key, nonce, plaintext, AAD=header)
record = header || ciphertext || tag:16-bytes
```

Version 1 defines flag bit 0 as `final`; all other flag bits are rejected.
Sequences start at zero and increase by one. An empty payload is permitted only
on a final record. Payload length is limited by both `max_record_size` and the
32-bit wire field. The record must have exactly the length declared by its
header.

## Security invariants to verify

1. A `(key, nonce_prefix, sequence)` tuple is never reused within a session.
2. Header fields are authenticated with the ciphertext.
3. Decryption never reports success or advances state before tag verification.
4. Tentative plaintext is wiped after authentication failure.
5. Validation errors and authentication failures do not advance stream state.
6. Missing, duplicate, and reordered records cannot be accepted by one session.
7. No call processes more than the configured payload bound.
8. Integer conversions and additions are safe on every supported pointer width.
9. Final sessions reject further records, and sequence exhaustion cannot wrap.
10. Project-owned secret-key storage is wiped on drop without introducing
    accidental `Clone` or `Debug` exposure.
11. The crate remains allocation-free, `no_std`, and free of unsafe project code.

## Threat model and trust boundaries

The attacker may completely control serialized records and may observe error
variants and timing. The attacker may interrupt a stream at any record. The
underlying AEAD primitive is assumed secure; reviewers should still verify its
correct use and enabled features.

The caller is trusted to:

- generate and durably enforce a unique 16-byte nonce prefix for every stream
  under a key;
- provision and erase keys outside the library safely;
- preserve record boundaries when calling `decrypt_next`;
- require `DecryptSession::is_finished()` before considering the stream
  complete; and
- avoid acting irreversibly on record plaintext when whole-stream completion is
  required by the application.

These are material limitations. The library cannot detect nonce-prefix reuse
across sessions. Reuse with the same key breaks XChaCha20-Poly1305 security. It
also cannot detect truncation if an application simply stops calling it; only
the authenticated final flag lets the application reject an incomplete stream.
Per-record authentication intentionally releases earlier records before the
entire stream has been authenticated.

`SecretKey` wipes only the key copy it owns. The constructor's source bytes,
copies made by the caller, compiler spills, device memory, and crash dumps are
outside that guarantee.

## Review questions

- Can unauthenticated header validation create a useful state or timing oracle?
- Should nonce-prefix generation be offered behind an optional RNG feature, or
  should prefix allocation/persistence remain entirely platform-owned?
- Should the API provide an explicit end-of-input check so truncation is harder
  to overlook?
- Is cross-protocol key separation required, or is the magic/version prefix an
  adequate domain boundary for intended deployments?
- Are record size and call-time bounds meaningful on representative targets,
  including authentication-failure paths?
- Does dependency key material receive the expected zeroization treatment under
  the exact disabled-default-feature configuration?
- Are error distinctions acceptable to expose to an active attacker?

## Verification plan

Before handoff, pin an audit commit and capture output from:

```sh
cargo fmt --manifest-path tricklecrypt/Cargo.toml --all -- --check
cargo test --manifest-path tricklecrypt/Cargo.toml --all-targets
cargo clippy --manifest-path tricklecrypt/Cargo.toml --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --manifest-path tricklecrypt/Cargo.toml --no-deps
cargo check --manifest-path tricklecrypt/Cargo.toml --target thumbv7em-none-eabihf
```

Also run the suite on Rust 1.81 (the declared MSRV), audit advisories and
licenses for the resolved dependency graph, fuzz header parsing and decryption,
and measure maximum-sized valid and invalid records on representative embedded
hardware.

The adversarial test matrix should cover every public error variant, every
state transition, all length boundaries, mutations of each authenticated header
field, ciphertext and tag mutations, retry after failure, and stable externally
generated wire-format vectors.

## Deliverables requested from the auditor

- findings ranked by severity, exploitability, and affected assumptions;
- a review of protocol construction and API misuse resistance;
- confirmation of the invariants above or a counterexample;
- reproducible tests for each finding;
- dependency and platform-scope observations separated from project-code
  findings; and
- a retest statement tied to the exact remediation commit.

Before commissioning the audit, choose supported targets, define a disclosure
contact and response expectations, add MSRV/dependency checks to CI, establish
fixed interoperability vectors, and freeze the protocol/API for the review.

