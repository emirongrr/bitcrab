//! Bitcoin P2P wire format encoding and decoding.
//!

pub mod decode;
pub mod encode;
pub mod error;

pub use decode::{BitcoinDecode, Decoder};
pub use encode::{BitcoinEncode, Encoder, U16BE, VarInt, VarList, VarStr};
pub use error::{DecodeError, EncodeError};