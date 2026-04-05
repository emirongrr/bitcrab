// Wire encoding roundtrip tests - inspired by Bitcoin Core's wire encoding tests

use bitcrab_common::wire::encode::Encoder;
use bitcrab_common::wire::decode::Decoder;

#[test]
fn test_encode_u32_roundtrip() {
    let value: u32 = 0x12345678;
    let encoded = Encoder::new().encode_field(&value).finish();
    
    let (decoded, _) = Decoder::new(&encoded).decode_field::<u32>("test").unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn test_encode_u64_roundtrip() {
    let value: u64 = 0x123456789ABCDEF0;
    let encoded = Encoder::new().encode_field(&value).finish();
    
    let (decoded, _) = Decoder::new(&encoded).decode_field::<u64>("test").unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn test_encode_boundary_values() {
    let test_cases = vec![
        0u32,
        u32::MAX,
        1u32,
        0xFFFFFFFFu32,
        0x80000000u32,
    ];
    
    for value in test_cases {
        let encoded = Encoder::new().encode_field(&value).finish();
        let (decoded, _) = Decoder::new(&encoded).decode_field::<u32>("test").unwrap();
        assert_eq!(decoded, value, "Failed roundtrip for value: {}", value);
    }
}

#[test]
fn test_encode_empty_vec() {
    let data: Vec<u8> = vec![];
    let encoded = Encoder::new()
        .encode_field(&(data.len() as u32))
        .finish();
    
    let (len, dec) = Decoder::new(&encoded).decode_field::<u32>("len").unwrap();
    assert_eq!(len, 0);
}

#[test]
fn test_encode_vec_with_data() {
    let data: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let encoded = Encoder::new()
        .encode_field(&(data.len() as u32))
        .finish();
    
    let (len, _) = Decoder::new(&encoded).decode_field::<u32>("len").unwrap();
    assert_eq!(len as usize, data.len());
}

#[test]
fn test_encode_multiple_fields() {
    let val1: u32 = 0xDEADBEEF;
    let val2: u64 = 0xCAFEBABEDEADBEEF;
    
    let encoded = Encoder::new()
        .encode_field(&val1)
        .encode_field(&val2)
        .finish();
    
    let (decoded1, dec) = Decoder::new(&encoded).decode_field::<u32>("val1").unwrap();
    let (decoded2, _) = dec.decode_field::<u64>("val2").unwrap();
    
    assert_eq!(decoded1, val1);
    assert_eq!(decoded2, val2);
}

#[test]
fn test_encode_consistency() {
    let value: u32 = 0x12345678;
    
    // Encode twice
    let encoded1 = Encoder::new().encode_field(&value).finish();
    let encoded2 = Encoder::new().encode_field(&value).finish();
    
    // Should produce identical output
    assert_eq!(encoded1, encoded2, "Encoding should be deterministic");
}
