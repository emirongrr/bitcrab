use bitcrab_common::types::block::*;


    /// The canonical correctness test.
    /// These values come from Bitcoin Core's `src/kernel/chainparams.cpp`.
    /// If this passes, serialize/deserialize and hash256 are correct.
    #[test]
    fn genesis_block_hash() {
        let header = BlockHeader {
            version: 1,
            prev_hash: BlockHash::ZERO,
            merkle_root: Hash256::from_bytes(
                hex::decode(
                    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            ),
            time: 1_231_006_505,
            bits: 0x1d00_ffff,
            nonce: 2_083_236_893,
        };
        assert_eq!(
            header.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        );
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let h = BlockHeader {
            version:     2,
            prev_hash:   BlockHash::from_bytes([0xAB; 32]),
            merkle_root: Hash256::from_bytes([0xCD; 32]),
            time:        1_700_000_000,
            bits:        0x1703_a30c,
            nonce:       99_999,
        };
        assert_eq!(BlockHeader::deserialize(&h.serialize()), h);
    }

    #[test]
    fn header_is_exactly_80_bytes() {
        let h = BlockHeader {
            version: 1, prev_hash: BlockHash::ZERO, merkle_root: Hash256::ZERO,
            time: 0, bits: 0, nonce: 0,
        };
        assert_eq!(h.serialize().len(), 80);
    }

    #[test]
    fn block_height_prev_at_genesis_is_none() {
        assert!(BlockHeight::GENESIS.prev().is_none());
        assert_eq!(BlockHeight(1).prev(), Some(BlockHeight::GENESIS));
    }
