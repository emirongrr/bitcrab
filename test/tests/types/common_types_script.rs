use bitcrab_common::types::script::*;


    #[test]
    fn empty_script() {
        let s = ScriptBuf::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn within_size_limit() {
        let small = ScriptBuf::from_bytes(vec![0x00; 100]);
        assert!(small.is_within_size_limit());

        let too_large = ScriptBuf::from_bytes(vec![0x00; MAX_SCRIPT_SIZE + 1]);
        assert!(!too_large.is_within_size_limit());
    }

    #[test]
    fn from_slice() {
        let bytes: &[u8] = &[0x76, 0xa9, 0x14];
        let script = ScriptBuf::from(bytes);
        assert_eq!(script.as_bytes(), bytes);
    }
