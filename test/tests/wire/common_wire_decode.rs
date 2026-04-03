use bitcrab_common::wire::decode::*;

    use crate::wire::encode::{BitcoinEncode, Encoder, VarStr};

    /// Simple struct — encode_field / decode_field pattern.
    #[derive(Debug, PartialEq)]
    struct Simple {
        a: u32,
        b: u64,
    }

    impl BitcoinEncode for Simple {
        fn encode(&self, enc: Encoder) -> Encoder {
            enc.encode_field(&self.a)
               .encode_field(&self.b)
        }
    }

    impl BitcoinDecode for Simple {
        fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
            let (a, dec) = dec.decode_field("a")?;
            let (b, dec) = dec.decode_field("b")?;
            Ok((Simple { a, b }, dec))
        }
    }

    #[test]
    fn simple_roundtrip() {
        let original = Simple { a: 0xDEAD_BEEF, b: 0x0102_0304_0506_0708 };
        let bytes = Encoder::new().encode_field(&original).finish();
        assert_eq!(bytes.len(), 12); // 4 + 8

        let (decoded, dec) = Simple::decode(Decoder::new(&bytes)).unwrap();
        dec.finish("Simple").unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn u32_le_encoding() {
        let bytes = Encoder::new().encode_field(&0x0102_0304u32).finish();
        assert_eq!(bytes, [0x04, 0x03, 0x02, 0x01]); // little-endian
    }

    #[test]
    fn var_str_roundtrip() {
        let ua = "/bitcrab:0.1.0/";
        let bytes = Encoder::new().encode_field(&VarStr(ua)).finish();
        // varint(15) + 15 bytes = 16 bytes total
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 15); // varint prefix
        let (decoded, dec) = Decoder::new(&bytes).read_var_str("ua").unwrap();
        dec.finish("var_str").unwrap();
        assert_eq!(decoded, ua);
    }

    #[test]
    fn varint_1_byte() {
        let bytes = Encoder::new().encode_field(&crate::wire::encode::VarInt(42)).finish();
        assert_eq!(bytes, [42]);
    }

    #[test]
    fn varint_3_byte() {
        // 0xFD..=0xFFFF → 0xFD prefix + 2 bytes LE
        let bytes = Encoder::new().encode_field(&crate::wire::encode::VarInt(300)).finish();
        assert_eq!(bytes[0], 0xFD);
        assert_eq!(bytes.len(), 3);
        let (v, _) = Decoder::new(&bytes).read_varint("v").unwrap();
        assert_eq!(v, 300);
    }

    #[test]
    fn trailing_bytes_detected() {
        let bytes = vec![1u8, 0, 0, 0, 0xFF]; // u32 + extra
        let (_, dec) = Decoder::new(&bytes).read_u32_le("v").unwrap();
        assert!(dec.finish("test").is_err());
    }

    #[test]
    fn optional_field_absent() {
        let bytes = Encoder::new().encode_field(&42u32).finish();
        let dec = Decoder::new(&bytes);
        let (v, dec): (u32, _) = dec.decode_field("v").unwrap();
        assert_eq!(v, 42);
        let (opt, _dec): (Option<u32>, _) = dec.decode_optional_field();
        assert!(opt.is_none()); // no bytes remain
    }

    #[test]
    fn bool_encoding() {
        let t = Encoder::new().encode_field(&true).finish();
        let f = Encoder::new().encode_field(&false).finish();
        assert_eq!(t, [0x01]);
        assert_eq!(f, [0x00]);
    }


    #[test]
fn port_must_use_u16be() {
    // Bitcoin port encoding is always big-endian
    // Bitcoin Core: CAddress port field in src/netaddress.h
    let port: u16 = 8333;
    let bytes = Encoder::new().encode_field(&U16BE(port)).finish();
    assert_eq!(bytes, [0x20, 0x8D]); // 8333 big-endian = 0x208D
    
    let (U16BE(decoded), dec) = U16BE::decode(Decoder::new(&bytes)).unwrap();
    dec.finish("port").unwrap();
    assert_eq!(decoded, 8333);
}

#[test]
fn fixed_array_roundtrip() {
    let hash = [0xABu8; 32];
    let bytes = Encoder::new().encode_field(&hash).finish();
    assert_eq!(bytes.len(), 32);
    let (decoded, dec): ([u8; 32], _) = Decoder::new(&bytes).decode_field("hash").unwrap();
    dec.finish("hash").unwrap();
    assert_eq!(decoded, hash);
}

#[test]
fn varint_decode_field() {
    use crate::wire::encode::VarInt;
    let bytes = Encoder::new().encode_field(&VarInt(2000)).finish();
    let (VarInt(v), dec): (VarInt, _) = Decoder::new(&bytes).decode_field("count").unwrap();
    dec.finish("count").unwrap();
    assert_eq!(v, 2000);
}
