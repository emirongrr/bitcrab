//! Consensus-independent signature experiments.
//!
//! This API deliberately does not participate in Bitcoin Script execution.
//! It lets benchmarks replay identical message/signature/public-key workloads
//! against classic and future post-quantum implementations.

use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFamily {
    ClassicSecp256k1,
    PostQuantumExperimental,
}

#[derive(Debug, Clone)]
pub struct SignatureWorkItem {
    pub message: [u8; 32],
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureBenchmarkResult {
    pub family: SignatureFamily,
    pub verified: usize,
    pub rejected: usize,
    pub elapsed: Duration,
}

#[derive(Debug, Error)]
pub enum SignatureExperimentError {
    #[error("invalid signature or public key encoding")]
    InvalidEncoding,
    #[error("post-quantum verifier is not configured")]
    PostQuantumVerifierUnavailable,
}

pub trait SignatureExperimentVerifier {
    fn family(&self) -> SignatureFamily;

    fn verify(&self, item: &SignatureWorkItem) -> Result<bool, SignatureExperimentError>;
}

pub struct ClassicSecp256k1Verifier;

impl SignatureExperimentVerifier for ClassicSecp256k1Verifier {
    fn family(&self) -> SignatureFamily {
        SignatureFamily::ClassicSecp256k1
    }

    fn verify(&self, item: &SignatureWorkItem) -> Result<bool, SignatureExperimentError> {
        use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

        let message = Message::from_digest(item.message);
        let signature = Signature::from_der(&item.signature)
            .map_err(|_| SignatureExperimentError::InvalidEncoding)?;
        let public_key = PublicKey::from_slice(&item.public_key)
            .map_err(|_| SignatureExperimentError::InvalidEncoding)?;
        Ok(Secp256k1::verification_only()
            .verify_ecdsa(&message, &signature, &public_key)
            .is_ok())
    }
}

pub fn benchmark_signature_workload(
    verifier: &dyn SignatureExperimentVerifier,
    workload: &[SignatureWorkItem],
) -> Result<SignatureBenchmarkResult, SignatureExperimentError> {
    let started = Instant::now();
    let mut verified = 0;
    let mut rejected = 0;

    for item in workload {
        if verifier.verify(item)? {
            verified += 1;
        } else {
            rejected += 1;
        }
    }

    Ok(SignatureBenchmarkResult {
        family: verifier.family(),
        verified,
        rejected,
        elapsed: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn classic_workload_benchmark_reports_verified_items() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let public = secret.public_key(&secp);
        let message = [7; 32];
        let signature = secp
            .sign_ecdsa(&secp256k1::Message::from_digest(message), &secret)
            .serialize_der()
            .to_vec();
        let workload = vec![SignatureWorkItem {
            message,
            signature,
            public_key: public.serialize().to_vec(),
        }];

        let result = benchmark_signature_workload(&ClassicSecp256k1Verifier, &workload).unwrap();

        assert_eq!(result.family, SignatureFamily::ClassicSecp256k1);
        assert_eq!(result.verified, 1);
        assert_eq!(result.rejected, 0);
    }
}
