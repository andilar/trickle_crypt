use core::fmt;

/// Errors returned while configuring or processing a record stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    InvalidMaxRecordSize,
    EmptyRecord,
    RecordTooLarge { len: usize, max: usize },
    OutputTooSmall { required: usize, available: usize },
    InputTooShort { minimum: usize, actual: usize },
    InvalidHeader,
    UnsupportedVersion(u8),
    UnexpectedSequence { expected: u64, actual: u64 },
    AuthenticationFailed,
    SequenceExhausted,
    AlreadyFinished,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaxRecordSize => formatter.write_str("invalid maximum record size"),
            Self::EmptyRecord => formatter.write_str("only the final record may be empty"),
            Self::RecordTooLarge { len, max } => {
                write!(formatter, "record length {len} exceeds maximum {max}")
            }
            Self::OutputTooSmall {
                required,
                available,
            } => write!(
                formatter,
                "output requires {required} bytes but only {available} are available"
            ),
            Self::InputTooShort { minimum, actual } => write!(
                formatter,
                "input requires at least {minimum} bytes but only {actual} are available"
            ),
            Self::InvalidHeader => formatter.write_str("invalid record header"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported record version {version}")
            }
            Self::UnexpectedSequence { expected, actual } => write!(
                formatter,
                "expected record sequence {expected} but received {actual}"
            ),
            Self::AuthenticationFailed => formatter.write_str("record authentication failed"),
            Self::SequenceExhausted => formatter.write_str("record sequence exhausted"),
            Self::AlreadyFinished => formatter.write_str("record stream is already finished"),
        }
    }
}

impl core::error::Error for Error {}
