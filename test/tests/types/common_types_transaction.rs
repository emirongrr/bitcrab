use bitcrab_common::types::amount::Amount;
use bitcrab_common::types::constants::COIN;
use bitcrab_common::types::hash::Txid;
use bitcrab_common::types::script::ScriptBuf;
use bitcrab_common::types::transaction::*;
use bitcrab_common::wire::{BitcoinDecode, BitcoinEncode, Decoder, Encoder};

#[test]
fn coinbase_outpoint() {
    assert!(OutPoint::COINBASE.is_coinbase());
    assert!(!OutPoint {
        txid: Txid::from_bytes([1u8; 32]),
        vout: 0
    }
    .is_coinbase());
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
        inputs: vec![],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(COIN).unwrap(),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::from_sat(COIN).unwrap(),
                script_pubkey: ScriptBuf::new(),
            },
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
        inputs: vec![witness_inp],
        outputs: vec![],
        lock_time: 0,
    };
    assert!(tx.is_segwit());
}

#[test]
fn legacy_transaction_decode_preserves_input_count() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(vec![0x51]),
            sequence: TxIn::SEQUENCE_FINAL,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000).unwrap(),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        lock_time: 0,
    };

    let encoded = tx.encode(Encoder::new()).finish();
    assert_ne!(
        encoded[4], 0,
        "legacy input count must not be a SegWit marker"
    );

    let (decoded, dec) = Transaction::decode(Decoder::new(&encoded)).unwrap();
    dec.finish("legacy tx").unwrap();
    assert_eq!(decoded.inputs.len(), 1);
    assert_eq!(decoded.outputs.len(), 1);
    assert_eq!(decoded, tx);
}

#[test]
fn segwit_transaction_roundtrip() {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::new(),
            sequence: TxIn::SEQUENCE_FINAL,
            witness: vec![vec![0x30, 0x44], vec![0x02, 0x01]],
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(2_000).unwrap(),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        lock_time: 0,
    };

    let encoded = tx.encode(Encoder::new()).finish();
    assert_eq!(&encoded[4..6], &[0, 1]);

    let (decoded, dec) = Transaction::decode(Decoder::new(&encoded)).unwrap();
    dec.finish("segwit tx").unwrap();
    assert_eq!(decoded, tx);
}
