use crate::types::amount::Amount;
use crate::types::block::{Block, BlockHeader};
use crate::types::hash::{BlockHash, Hash256, Txid};
use crate::types::script::ScriptBuf;
use crate::types::transaction::{OutPoint, Transaction, TxIn, TxOut};

/// Professional Bitcoin Genesis configuration.
///
/// Matches Bitcoin Core's `CreateGenesisBlock` engine.
/// Network parameters are hardcoded mirroring `chainparams.cpp`.
#[derive(Debug, Clone)]
pub struct Genesis {
    /// Block version
    pub version: i32,
    /// Unix timestamp
    pub timestamp: u32,
    /// Proof of work target (compact representation)
    pub bits: u32,
    /// Proof of work nonce
    pub nonce: u32,
    /// The historic coinbase message (e.g. "The Times 03/Jan/2009...")
    pub message: String,
    /// The output script for the genesis coinbase transaction
    pub output_script: ScriptBuf,
    /// The initial block reward
    pub reward: Amount,
}

impl Genesis {
    /// Standard Mainnet Genesis configuration.
    pub fn mainnet() -> Self {
        Self {
            version: 1,
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
            message: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".to_string(),
            output_script: ScriptBuf::from_bytes(hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap()),
            reward: Amount::from_sat(5000000000).unwrap(),
        }
    }
    /// Standard Testnet3 Genesis configuration.
    pub fn testnet3() -> Self {
        Self {
            version: 1,
            timestamp: 1296688602,
            bits: 0x1d00ffff,
            nonce: 414098458,
            message: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".to_string(),
            output_script: ScriptBuf::from_bytes(hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap()),
            reward: Amount::from_sat(5000000000).unwrap(),
        }
    }

    /// Standard Signet Genesis configuration.
    pub fn signet() -> Self {
        Self {
            version: 1,
            timestamp: 1598918400,
            bits: 0x1e0377ae,
            nonce: 52613770,
            message: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".to_string(),
            output_script: ScriptBuf::from_bytes(hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap()),
            reward: Amount::from_sat(5000000000).unwrap(),
        }
    }

    /// Standard Regtest Genesis configuration.
    pub fn regtest() -> Self {
        Self {
            version: 1,
            timestamp: 1296688602,
            bits: 0x207fffff,
            nonce: 2,
            message: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".to_string(),
            output_script: ScriptBuf::from_bytes(hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap()),
            reward: Amount::from_sat(5000000000).unwrap(),
        }
    }

    /// Returns the standard genesis for a given Magic network.
    pub fn from_magic(magic: crate::types::magic::Magic) -> Self {
        use crate::types::magic::Magic;
        match magic {
            Magic::MAINNET => Self::mainnet(),
            Magic::TESTNET3 => Self::testnet3(),
            Magic::SIGNET => Self::signet(),
            Magic::REGTEST => Self::regtest(),
            _ => Self::signet(), // Default to signet for safety in this context
        }
    }

    /// Build the actual Block from these parameters.
    ///
    /// Matches Bitcoin Core's `CreateGenesisBlock` implementation.
    pub fn build(&self) -> Block {
        // 1. Construct Coinbase Transaction scriptSig
        let mut script_sig = Vec::new();
        // 1.1 Difficulty bits (Standardized to 486604799 in all Bitcoin networks' genesis)
        script_sig.push(0x04);
        script_sig.extend_from_slice(&486604799u32.to_le_bytes());
        // 1.2 "4" as script number
        script_sig.push(0x01);
        script_sig.push(0x04);
        // 1.3 Message
        script_sig.push(self.message.len() as u8);
        script_sig.extend_from_slice(self.message.as_bytes());

        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: 0xffffffff,
                },
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: self.reward,
                script_pubkey: self.output_script.clone(),
            }],
            lock_time: 0,
        };

        let mut block = Block {
            header: BlockHeader {
                version: self.version,
                prev_hash: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: self.timestamp,
                bits: self.bits,
                nonce: self.nonce,
            },
            transactions: vec![coinbase_tx],
        };

        block.header.merkle_root = block.compute_merkle_root();
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_genesis_hash() {
        let block = Genesis::mainnet().build();
        let expected_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let expected_merkle = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

        assert_eq!(
            block.header.block_hash().to_string(),
            expected_hash,
            "Mainnet Block Hash mismatch"
        );
        assert_eq!(
            block.header.merkle_root.to_string(),
            expected_merkle,
            "Mainnet Merkle Root mismatch"
        );
    }

    #[test]
    fn test_signet_genesis_hash() {
        let block = Genesis::signet().build();
        let expected_hash = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
        let expected_merkle = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

        assert_eq!(
            block.header.block_hash().to_string(),
            expected_hash,
            "Signet Block Hash mismatch"
        );
        assert_eq!(
            block.header.merkle_root.to_string(),
            expected_merkle,
            "Signet Merkle Root mismatch"
        );
    }

    #[test]
    fn test_testnet3_genesis_hash() {
        let block = Genesis::testnet3().build();
        let expected_hash = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
        let expected_merkle = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

        assert_eq!(
            block.header.block_hash().to_string(),
            expected_hash,
            "Testnet3 Block Hash mismatch"
        );
        assert_eq!(
            block.header.merkle_root.to_string(),
            expected_merkle,
            "Testnet3 Merkle Root mismatch"
        );
    }

    #[test]
    fn test_regtest_genesis_hash() {
        let block = Genesis::regtest().build();
        let expected_hash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
        assert_eq!(
            block.header.block_hash().to_string(),
            expected_hash,
            "Regtest Block Hash mismatch"
        );
    }

    #[test]
    fn test_genesis_fields() {
        // Detailed check of individual fields for Mainnet
        let mainnet = Genesis::mainnet();
        assert_eq!(mainnet.version, 1);
        assert_eq!(mainnet.timestamp, 1231006505);
        assert_eq!(mainnet.bits, 0x1d00ffff);
        assert_eq!(mainnet.nonce, 2083236893);
        assert_eq!(mainnet.reward.to_sat(), 5000000000);
        assert_eq!(
            mainnet.message,
            "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
        );

        // Detailed check of individual fields for Signet
        let signet = Genesis::signet();
        assert_eq!(signet.version, 1);
        assert_eq!(signet.timestamp, 1598918400);
        assert_eq!(signet.bits, 0x1e0377ae);
        assert_eq!(signet.nonce, 52613770);
        assert_eq!(signet.reward.to_sat(), 5000000000);
        assert_eq!(
            signet.message,
            "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
        );

        // Detailed check of individual fields for Regtest
        let regtest = Genesis::regtest();
        assert_eq!(regtest.version, 1);
        assert_eq!(regtest.timestamp, 1296688602);
        assert_eq!(regtest.bits, 0x207fffff);
        assert_eq!(regtest.nonce, 2);
    }
}
