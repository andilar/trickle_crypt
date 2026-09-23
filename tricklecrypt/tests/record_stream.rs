use tricklecrypt::{
    DecryptSession, EncryptSession, Error, NoncePrefix, SecretKey, HEADER_SIZE, TAG_SIZE,
};

const MAX_RECORD: usize = 32;
const OVERHEAD: usize = HEADER_SIZE + TAG_SIZE;
const KEY: [u8; 32] = [0x42; 32];
const PREFIX: NoncePrefix = NoncePrefix::new([0x24; 16]);

fn encryptor() -> EncryptSession {
    EncryptSession::new(SecretKey::new(KEY), PREFIX, MAX_RECORD).unwrap()
}

fn decryptor() -> DecryptSession {
    DecryptSession::new(SecretKey::new(KEY), PREFIX, MAX_RECORD).unwrap()
}

#[test]
fn round_trip_preserves_multiple_records() {
    let mut encryptor = encryptor();
    let mut decryptor = decryptor();
    let mut first_record = [0_u8; MAX_RECORD + OVERHEAD];
    let mut final_record = [0_u8; MAX_RECORD + OVERHEAD];
    let mut plaintext = [0_u8; MAX_RECORD];

    let first = encryptor
        .encrypt_next(b"temperature=21.4", &mut first_record, false)
        .unwrap();
    let final_progress = encryptor
        .encrypt_next(b"humidity=48", &mut final_record, true)
        .unwrap();

    let decrypted_first = decryptor
        .decrypt_next(&first_record[..first.written], &mut plaintext)
        .unwrap();
    assert_eq!(&plaintext[..decrypted_first.written], b"temperature=21.4");
    assert!(!decrypted_first.final_record);

    let decrypted_final = decryptor
        .decrypt_next(&final_record[..final_progress.written], &mut plaintext)
        .unwrap();
    assert_eq!(&plaintext[..decrypted_final.written], b"humidity=48");
    assert!(decrypted_final.final_record);
    assert!(encryptor.is_finished());
    assert!(decryptor.is_finished());
}

#[test]
fn tampering_is_rejected_and_output_is_wiped() {
    let mut record = [0_u8; MAX_RECORD + OVERHEAD];
    let progress = encryptor()
        .encrypt_next(b"authenticated", &mut record, true)
        .unwrap();
    record[HEADER_SIZE + 2] ^= 1;

    let mut output = [0xAA_u8; MAX_RECORD];
    let error = decryptor()
        .decrypt_next(&record[..progress.written], &mut output)
        .unwrap_err();

    assert_eq!(error, Error::AuthenticationFailed);
    assert_eq!(&output[..b"authenticated".len()], &[0_u8; 13]);
}

#[test]
fn wrong_key_is_rejected() {
    let mut record = [0_u8; MAX_RECORD + OVERHEAD];
    let progress = encryptor()
        .encrypt_next(b"secret", &mut record, true)
        .unwrap();
    let mut decryptor =
        DecryptSession::new(SecretKey::new([0x99; 32]), PREFIX, MAX_RECORD).unwrap();

    let error = decryptor
        .decrypt_next(&record[..progress.written], &mut [0_u8; MAX_RECORD])
        .unwrap_err();
    assert_eq!(error, Error::AuthenticationFailed);
}

#[test]
fn reordered_records_are_rejected() {
    let mut encryptor = encryptor();
    let mut first_record = [0_u8; MAX_RECORD + OVERHEAD];
    let mut second_record = [0_u8; MAX_RECORD + OVERHEAD];
    encryptor
        .encrypt_next(b"first", &mut first_record, false)
        .unwrap();
    let second = encryptor
        .encrypt_next(b"second", &mut second_record, true)
        .unwrap();

    let error = decryptor()
        .decrypt_next(&second_record[..second.written], &mut [0_u8; MAX_RECORD])
        .unwrap_err();
    assert_eq!(
        error,
        Error::UnexpectedSequence {
            expected: 0,
            actual: 1,
        }
    );
}

#[test]
fn configured_record_limit_is_enforced() {
    let error = encryptor()
        .encrypt_next(
            &[0_u8; MAX_RECORD + 1],
            &mut [0_u8; MAX_RECORD + OVERHEAD + 1],
            true,
        )
        .unwrap_err();
    assert_eq!(
        error,
        Error::RecordTooLarge {
            len: MAX_RECORD + 1,
            max: MAX_RECORD,
        }
    );
}

#[test]
fn output_capacity_is_checked_before_encryption() {
    let error = encryptor()
        .encrypt_next(b"payload", &mut [0_u8; 8], true)
        .unwrap_err();
    assert_eq!(
        error,
        Error::OutputTooSmall {
            required: b"payload".len() + OVERHEAD,
            available: 8,
        }
    );
}

#[test]
fn empty_final_record_is_supported() {
    let mut record = [0_u8; OVERHEAD];
    let progress = encryptor().encrypt_next(b"", &mut record, true).unwrap();
    let decrypted = decryptor()
        .decrypt_next(&record[..progress.written], &mut [])
        .unwrap();

    assert_eq!(decrypted.written, 0);
    assert!(decrypted.final_record);
}

#[test]
fn finished_session_cannot_be_reused() {
    let mut encryptor = encryptor();
    let mut record = [0_u8; MAX_RECORD + OVERHEAD];
    encryptor.encrypt_next(b"final", &mut record, true).unwrap();

    assert_eq!(
        encryptor
            .encrypt_next(b"too late", &mut record, true)
            .unwrap_err(),
        Error::AlreadyFinished
    );
}

#[test]
fn invalid_configuration_and_empty_non_final_record_are_rejected() {
    assert!(matches!(
        EncryptSession::new(SecretKey::new(KEY), PREFIX, 0),
        Err(Error::InvalidMaxRecordSize)
    ));

    let error = encryptor()
        .encrypt_next(b"", &mut [0_u8; OVERHEAD], false)
        .unwrap_err();
    assert_eq!(error, Error::EmptyRecord);
}

#[test]
fn malformed_headers_are_rejected() {
    let mut output = [0_u8; MAX_RECORD];

    assert_eq!(
        decryptor().decrypt_next(&[0_u8; OVERHEAD - 1], &mut output),
        Err(Error::InputTooShort {
            minimum: OVERHEAD,
            actual: OVERHEAD - 1,
        })
    );

    let mut record = encrypted_record(b"payload", true);
    record[0] ^= 1;
    assert_eq!(
        decryptor().decrypt_next(&record, &mut output),
        Err(Error::InvalidHeader)
    );

    let mut record = encrypted_record(b"payload", true);
    record[2] = 2;
    assert_eq!(
        decryptor().decrypt_next(&record, &mut output),
        Err(Error::UnsupportedVersion(2))
    );

    let mut record = encrypted_record(b"payload", true);
    record[3] = 0x80;
    assert_eq!(
        decryptor().decrypt_next(&record, &mut output),
        Err(Error::InvalidHeader)
    );
}

#[test]
fn declared_length_and_decryption_output_capacity_are_checked() {
    let mut record = encrypted_record(b"payload", true);
    record[15] += 1;
    assert_eq!(
        decryptor().decrypt_next(&record, &mut [0_u8; MAX_RECORD]),
        Err(Error::InvalidHeader)
    );

    let record = encrypted_record(b"payload", true);
    assert_eq!(
        decryptor().decrypt_next(&record, &mut [0_u8; 6]),
        Err(Error::OutputTooSmall {
            required: 7,
            available: 6,
        })
    );
}

#[test]
fn nonce_prefix_mismatch_is_rejected() {
    let record = encrypted_record(b"payload", true);
    let mut decryptor = DecryptSession::new(
        SecretKey::new(KEY),
        NoncePrefix::new([0x25; 16]),
        MAX_RECORD,
    )
    .unwrap();

    assert_eq!(
        decryptor.decrypt_next(&record, &mut [0_u8; MAX_RECORD]),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn authentication_failure_does_not_advance_session() {
    let record = encrypted_record(b"payload", true);
    let mut corrupted = record.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut decryptor = decryptor();
    let mut output = [0xAA_u8; MAX_RECORD];

    assert_eq!(
        decryptor.decrypt_next(&corrupted, &mut output),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(&output[..7], &[0_u8; 7]);
    assert!(!decryptor.is_finished());

    let progress = decryptor.decrypt_next(&record, &mut output).unwrap();
    assert_eq!(&output[..progress.written], b"payload");
    assert!(decryptor.is_finished());
}

#[test]
fn duplicate_record_and_finished_decryptor_are_rejected() {
    let mut encryptor = encryptor();
    let mut first = [0_u8; MAX_RECORD + OVERHEAD];
    let first_len = encryptor
        .encrypt_next(b"first", &mut first, false)
        .unwrap()
        .written;
    let mut final_record = [0_u8; MAX_RECORD + OVERHEAD];
    let final_len = encryptor
        .encrypt_next(b"final", &mut final_record, true)
        .unwrap()
        .written;
    let mut decryptor = decryptor();
    let mut output = [0_u8; MAX_RECORD];

    decryptor
        .decrypt_next(&first[..first_len], &mut output)
        .unwrap();
    assert_eq!(
        decryptor.decrypt_next(&first[..first_len], &mut output),
        Err(Error::UnexpectedSequence {
            expected: 1,
            actual: 0,
        })
    );

    decryptor
        .decrypt_next(&final_record[..final_len], &mut output)
        .unwrap();
    assert_eq!(
        decryptor.decrypt_next(&final_record[..final_len], &mut output),
        Err(Error::AlreadyFinished)
    );
}

#[test]
fn version_one_wire_format_vector_is_stable() {
    let record = encrypted_record(b"secret", true);
    let expected: &[u8] = &[
        0x54, 0x43, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x91, 0x54, 0xc7, 0xb1, 0xcd, 0xba, 0x18, 0x20, 0xf6, 0xfd, 0xa4, 0xac, 0x5c, 0xf5,
        0xd3, 0x0b, 0xd9, 0x72, 0x11, 0x16, 0x8a, 0x52,
    ];
    assert_eq!(record, expected);
}

fn encrypted_record(plaintext: &[u8], final_record: bool) -> Vec<u8> {
    let mut record = vec![0_u8; plaintext.len() + OVERHEAD];
    let progress = encryptor()
        .encrypt_next(plaintext, &mut record, final_record)
        .unwrap();
    record.truncate(progress.written);
    record
}
