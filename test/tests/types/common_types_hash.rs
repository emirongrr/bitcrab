use bitcrab_common::types::hash::*;


    #[test]
    fn hash256_empty_input_known_vector() {
        assert_eq!(
            hex::encode(hash256(b"")),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        );
    }

    #[test]
    fn hash160_empty_input_known_vector() {
        assert_eq!(
            hex::encode(hash160(b"")),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
        );
    }

    #[test]
    fn display_reverses_bytes() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;
        let h = Hash256::from_bytes(bytes);
        let s = h.to_string();
        assert!(s.starts_with("00"));
        assert!(s.ends_with("cdab"));
    }
    #[test]
    fn genesis_txid_known_value() {
        let txid = Txid::from_bytes(
            hex::decode(
                "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            )
            .unwrap()
            .try_into()
            .unwrap(),
        );
            assert_eq!(
                txid.to_string(),
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            );
    }

    #[test]
    fn txid_and_blockhash_are_distinct_types() {
        let _t: Txid      = Txid::ZERO;
        let _b: BlockHash = BlockHash::ZERO;
    }

    #[test]
    fn is_zero_works() {
        assert!(Hash256::ZERO.is_zero());
        assert!(!Hash256::from_bytes([1u8; 32]).is_zero());
    }
