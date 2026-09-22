use crate::Error;

pub const KEY_SIZE: usize = 32;
pub const NONCE_PREFIX_SIZE: usize = 16;
pub const HEADER_SIZE: usize = 16;
pub const TAG_SIZE: usize = 16;
pub(crate) const RECORD_OVERHEAD: usize = HEADER_SIZE + TAG_SIZE;

const MAGIC: [u8; 2] = *b"TC";
const VERSION: u8 = 1;
const FINAL_FLAG: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    pub sequence: u64,
    pub payload_len: usize,
    pub final_record: bool,
}

impl Header {
    pub fn encode(self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0_u8; HEADER_SIZE];
        bytes[..2].copy_from_slice(&MAGIC);
        bytes[2] = VERSION;
        bytes[3] = u8::from(self.final_record) * FINAL_FLAG;
        bytes[4..12].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[12..16].copy_from_slice(&(self.payload_len as u32).to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::InputTooShort {
                minimum: HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        if bytes[..2] != MAGIC {
            return Err(Error::InvalidHeader);
        }
        if bytes[2] != VERSION {
            return Err(Error::UnsupportedVersion(bytes[2]));
        }
        if bytes[3] & !FINAL_FLAG != 0 {
            return Err(Error::InvalidHeader);
        }

        let mut sequence_bytes = [0_u8; 8];
        sequence_bytes.copy_from_slice(&bytes[4..12]);
        let sequence = u64::from_be_bytes(sequence_bytes);

        let mut length_bytes = [0_u8; 4];
        length_bytes.copy_from_slice(&bytes[12..16]);
        let payload_len = u32::from_be_bytes(length_bytes) as usize;

        Ok(Self {
            sequence,
            payload_len,
            final_record: bytes[3] & FINAL_FLAG != 0,
        })
    }
}
