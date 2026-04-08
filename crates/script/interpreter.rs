//! Bitcoin Script Interpreter Core.
//!
//! Matches Bitcoin Core's `src/script/interpreter.cpp`.

use super::opcode::Opcode;
use super::stack::{ScriptStack, StackError};
use bitcrab_common::types::hash::{hash160, hash256};
use bitcrab_common::types::script::ScriptBuf;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InterpreterError {
    #[error("script execution error: {0}")]
    Stack(#[from] StackError),
    #[error("invalid opcode: {0:02x}")]
    InvalidOpcode(u8),
    #[error("script failed (OP_VERIFY or final stack state)")]
    Failed,
    #[error("non-canonical signature or pubkey")]
    InvalidCryptoData,
    #[error("unsupported opcode: {0:?}")]
    UnsupportedOpcode(Opcode),
    #[error("truncated script")]
    TruncatedScript,
}

pub struct ScriptInterpreter {
    stack: ScriptStack,
    sighash: [u8; 32],
}

impl ScriptInterpreter {
    pub fn new(sighash: [u8; 32]) -> Self {
        Self {
            stack: ScriptStack::new(),
            sighash,
        }
    }

    /// Primary entry point for verifying an input's script.
    pub fn verify_script(
        script_sig: &ScriptBuf,
        script_pubkey: &ScriptBuf,
        _witness: &[Vec<u8>], // TODO: Support SegWit
        sighash: [u8; 32],    // Pre-computed transaction digest
    ) -> Result<bool, InterpreterError> {
        let mut interpreter = Self::new(sighash);

        // 1. Execute scriptSig (pushes data onto stack)
        interpreter.execute(script_sig)?;

        // 2. Execute scriptPubKey (consumes/verifies stack data)
        interpreter.execute(script_pubkey)?;

        // 3. Script is successful if stack is not empty and top is true
        if interpreter.stack.is_empty() {
            return Ok(false);
        }

        let top = interpreter.stack.pop()?;
        Ok(Self::cast_to_bool(&top))
    }

    pub fn execute(&mut self, script: &ScriptBuf) -> Result<(), InterpreterError> {
        let bytes = script.as_bytes();
        let mut pc = 0;

        while pc < bytes.len() {
            let opcode_byte = bytes[pc];
            pc += 1;

            if opcode_byte <= 75 {
                // PUSHBYTES: The value is the length
                let len = opcode_byte as usize;
                if pc + len > bytes.len() {
                    return Err(InterpreterError::TruncatedScript);
                }
                self.stack.push(bytes[pc..pc + len].to_vec())?;
                pc += len;
            } else {
                let opcode = Opcode::from(opcode_byte);
                match opcode {
                    Opcode::OP_DUP => {
                        self.stack.dup()?;
                    }
                    Opcode::OP_HASH160 => {
                        let data = self.stack.pop()?;
                        self.stack.push(hash160(&data).to_vec())?;
                    }
                    Opcode::OP_EQUAL => {
                        let a = self.stack.pop()?;
                        let b = self.stack.pop()?;
                        self.stack.push(if a == b { vec![1] } else { vec![] })?;
                    }
                    Opcode::OP_VERIFY => {
                        let top = self.stack.pop()?;
                        if !Self::cast_to_bool(&top) {
                            return Err(InterpreterError::Failed);
                        }
                    }
                    Opcode::OP_EQUALVERIFY => {
                        let a = self.stack.pop()?;
                        let b = self.stack.pop()?;
                        if a != b {
                            return Err(InterpreterError::Failed);
                        }
                    }
                    Opcode::OP_CHECKSIG => {
                        let pubkey_bytes = self.stack.pop()?;
                        let sig_bytes = self.stack.pop()?;

                        // Bitcoin Rule: Empty signature is treated as success-fails-false (fails verification but doesn't crash)
                        if sig_bytes.is_empty() {
                            self.stack.push(vec![])?;
                        } else {
                            // 1. Strip sighash type byte (last byte) from DER signature
                            let (sig_der, _sighash_type) = sig_bytes.split_at(sig_bytes.len() - 1);

                            // 2. Verify using secp256k1
                            let secp = Secp256k1::verification_only();

                            let msg = Message::from_digest(self.sighash);
                            let pubkey = PublicKey::from_slice(&pubkey_bytes)
                                .map_err(|_| InterpreterError::InvalidCryptoData)?;
                            let sig = Signature::from_der(sig_der)
                                .map_err(|_| InterpreterError::InvalidCryptoData)?;

                            if secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok() {
                                self.stack.push(vec![1])?;
                            } else {
                                self.stack.push(vec![])?;
                            }
                        }
                    }
                    Opcode::OP_RETURN => return Err(InterpreterError::Failed),
                    _ => return Err(InterpreterError::UnsupportedOpcode(opcode)),
                }
            }
        }

        Ok(())
    }

    /// Cast stack data to boolean according to Bitcoin rules.
    ///
    /// Empty or all-zeros is false. Anything else is true.
    fn cast_to_bool(data: &[u8]) -> bool {
        for &b in data {
            if b != 0 {
                return true;
            }
        }
        false
    }
}
