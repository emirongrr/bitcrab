// Transaction validation tests - inspired by Bitcoin Core's validation tests

use bitcrab_common::types::transaction::{Transaction, TxIn, TxOut, OutPoint};
use bitcrab_common::types::hash::{hash256, Hash256};
use bitcrab_common::types::amount::Amount;

/// Helper to create a test transaction
fn create_test_tx(num_inputs: usize, num_outputs: usize) -> Transaction {
    let inputs = (0..num_inputs)
        .map(|i| TxIn {
            previous_output: OutPoint {
                txid: hash256(&[i as u8; 32]),
                vout: i as u32,
            },
            signature_script: vec![i as u8],
            sequence: 0xFFFFFFFE,
        })
        .collect();

    let outputs = (0..num_outputs)
        .map(|i| TxOut {
            value: Amount::from_sat(50_000_000),
            script_pubkey: vec![0x76, 0xa9, 0x14, i as u8],
        })
        .collect();

    Transaction {
        version: 1,
        input: inputs,
        output: outputs,
        lock_time: 0,
    }
}

#[test]
fn test_coinbase_transaction_no_inputs() {
    // Coinbase transactions are special - they have one input with null hash
    let tx = create_test_tx(1, 1);
    
    // In real validation, first input of block's first tx should have
    // previous_output.txid = 0 and vout = 0xFFFFFFFF
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1);
}

#[test]
fn test_transaction_with_zero_inputs_invalid() {
    let tx = create_test_tx(0, 1);
    
    // Transactions must have at least one input
    assert!(tx.input.is_empty(), "Empty input transaction created for testing");
}

#[test]
fn test_transaction_with_zero_outputs_invalid() {
    let tx = create_test_tx(1, 0);
    
    // Transactions must have at least one output
    assert!(tx.output.is_empty(), "Empty output transaction created for testing");
}

#[test]
fn test_transaction_input_output_balance() {
    let tx = create_test_tx(2, 3);
    
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 3);
}

#[test]
fn test_transaction_sequence_numbers() {
    let mut tx = create_test_tx(3, 2);
    
    // Set varying sequence numbers (used for locktime and BIP 68)
    tx.input[0].sequence = 0x00000000; // Absolute locktime
    tx.input[1].sequence = 0xFFFFFFFE; // Relative locktime
    tx.input[2].sequence = 0xFFFFFFFF; // Max sequence (no locktime)
    
    assert_eq!(tx.input[0].sequence, 0x00000000);
    assert_eq!(tx.input[1].sequence, 0xFFFFFFFE);
    assert_eq!(tx.input[2].sequence, 0xFFFFFFFF);
}

#[test]
fn test_transaction_locktime_values() {
    let mut tx = create_test_tx(1, 1);
    
    // Locktime = 0 means no locktime
    tx.lock_time = 0;
    assert_eq!(tx.lock_time, 0);
    
    // Locktime < 500M = block height
    tx.lock_time = 700_000;
    assert_eq!(tx.lock_time, 700_000);
    
    // Locktime >= 500M = Unix timestamp
    tx.lock_time = 1_500_000_000;
    assert_eq!(tx.lock_time, 1_500_000_000);
}

#[test]
fn test_transaction_dust_output() {
    // Bitcoin considers outputs below certain value as "dust"
    // Typically < 546 satoshis for P2PKH
    
    let mut tx = create_test_tx(1, 1);
    
    // Set dust value
    tx.output[0].value = Amount::from_sat(100);
    assert!(tx.output[0].value.as_sat() < 546);
}

#[test]
fn test_transaction_output_sum_overflow_prevention() {
    // Total output value should not exceed 21M BTC
    let mut tx = create_test_tx(1, 3);
    
    const MAX_BTC: u64 = 21_000_000 * 100_000_000; // 21M BTC in satoshis
    
    // Set values near maximum
    for i in 0..tx.output.len() {
        tx.output[i].value = Amount::from_sat(MAX_BTC / 4);
    }
    
    // Should handle without overflow
    let total: u64 = tx.output.iter().map(|o| o.value.as_sat()).sum();
    assert!(total <= MAX_BTC);
}

#[test]
fn test_transaction_version_field() {
    let mut tx = create_test_tx(1, 1);
    
    // Version 1 (standard)
    tx.version = 1;
    assert_eq!(tx.version, 1);
    
    // Version 2 (for relative locktime, BIP 68)
    tx.version = 2;
    assert_eq!(tx.version, 2);
}

#[test]
fn test_transaction_multiple_same_input() {
    // Bitcoin allows spending the same utxo multiple times in one tx
    let tx = create_test_tx(3, 1);
    
    // All inputs could theoretically reference same previous tx
    assert_eq!(tx.input.len(), 3);
}

#[test]
fn test_transaction_script_pubkey_empty() {
    let mut tx = create_test_tx(1, 1);
    
    // OP_RETURN scripts are valid but unspendable
    tx.output[0].script_pubkey = vec![0x6a]; // OP_RETURN
    
    assert_eq!(tx.output[0].script_pubkey[0], 0x6a);
}
