use bitcrab_common::types::transaction::*;

    use crate::types::constants::COIN;

    #[test]
    fn coinbase_outpoint() {
        assert!(OutPoint::COINBASE.is_coinbase());
        assert!(!OutPoint { txid: Txid::from_bytes([1u8; 32]), vout: 0 }.is_coinbase());
    }

    #[test]
    fn rbf_signalling() {
        let mut inp = TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::new(),
            sequence: TxIn::SEQUENCE_FINAL,
            witness: vec![],
        };
        assert!(!inp.signals_rbf());

        inp.sequence = 0xFFFF_FFFE;
        assert!(!inp.signals_rbf()); // exactly at threshold, not below

        inp.sequence = 0xFFFF_FFFD;
        assert!(inp.signals_rbf());
    }

    #[test]
    fn output_value_sum() {
        let tx = Transaction {
            version: 1,
            input: vec![],
            output: vec![
                TxOut { value: Amount::from_sat(COIN).unwrap(), script_pubkey: ScriptBuf::new() },
                TxOut { value: Amount::from_sat(COIN).unwrap(), script_pubkey: ScriptBuf::new() },
            ],
            lock_time: 0,
        };
        assert_eq!(tx.output_value().unwrap().to_sat(), 2 * COIN);
    }

    #[test]
    fn segwit_detection() {
        let witness_inp = TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::new(),
            sequence: TxIn::SEQUENCE_FINAL,
            witness: vec![vec![0x01, 0x02]],
        };
        let tx = Transaction {
            version: 2,
            input: vec![witness_inp],
            output: vec![],
            lock_time: 0,
        };
        assert!(tx.is_segwit());
    }
