//! Disk position logic.

use crate::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder},
    error::DecodeError,
};

/// A pointer to a record's data within the flat file sequence.
///
/// Serialised as 8 bytes: `file (4 LE) + offset (4 LE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
pub struct FlatFilePos {
    pub file: u32,
    pub offset: u32,
}

impl FlatFilePos {
    pub const fn new(file: u32, offset: u32) -> Self {
        Self { file, offset }
    }
}

impl BitcoinEncode for FlatFilePos {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.file).encode_field(&self.offset)
    }
}

impl BitcoinDecode for FlatFilePos {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (file, dec) = dec.decode_field::<u32>("FlatFilePos::file")?;
        let (offset, dec) = dec.decode_field::<u32>("FlatFilePos::offset")?;
        Ok((FlatFilePos { file, offset }, dec))
    }
}

impl std::fmt::Display for FlatFilePos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "f{:05}:o{}", self.file, self.offset)
    }
}
