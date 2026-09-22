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
    let mut decryptor = DecryptSession::new(
        SecretKey::new([0x99; 32]),
        PREFIX,
        MAX_RECORD,
    )
    .unwrap();

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
