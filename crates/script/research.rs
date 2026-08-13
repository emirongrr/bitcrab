//! Reproducible models for classic and post-quantum Bitcoin authorization.
//!
//! These types model encoded size and Bitcoin weight. They do not claim
//! cryptographic security or historical ownership.

use std::fmt;
use thiserror::Error;

pub const RESEARCH_MODEL_VERSION: &str = "bitcrab-authorization-model-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    EcdsaSecp256k1,
    SchnorrSecp256k1,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsa128s,
    SlhDsa128f,
}

impl SignatureScheme {
    pub const ALL: [Self; 7] = [
        Self::EcdsaSecp256k1,
        Self::SchnorrSecp256k1,
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
        Self::SlhDsa128s,
        Self::SlhDsa128f,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::EcdsaSecp256k1 => "ecdsa-secp256k1",
            Self::SchnorrSecp256k1 => "schnorr-secp256k1",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
            Self::SlhDsa128s => "slh-dsa-128s",
            Self::SlhDsa128f => "slh-dsa-128f",
        }
    }

    pub const fn public_key_bytes(self) -> u64 {
        match self {
            Self::EcdsaSecp256k1 => 33,
            Self::SchnorrSecp256k1 => 32,
            Self::MlDsa44 => 1_312,
            Self::MlDsa65 => 1_952,
            Self::MlDsa87 => 2_592,
            Self::SlhDsa128s | Self::SlhDsa128f => 32,
        }
    }

    pub const fn signature_bytes(self) -> u64 {
        match self {
            // ECDSA is variable-length DER. The model uses the common
            // 71-byte signature plus the Bitcoin sighash byte.
            Self::EcdsaSecp256k1 => 72,
            // BIP340 signature with Bitcoin SIGHASH_DEFAULT.
            Self::SchnorrSecp256k1 => 64,
            Self::MlDsa44 => 2_420,
            Self::MlDsa65 => 3_309,
            Self::MlDsa87 => 4_627,
            Self::SlhDsa128s => 7_856,
            Self::SlhDsa128f => 17_088,
        }
    }

    pub const fn standard_reference(self) -> &'static str {
        match self {
            Self::EcdsaSecp256k1 => "Bitcoin legacy ECDSA model",
            Self::SchnorrSecp256k1 => "BIP340 Schnorr model",
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => "NIST FIPS 204",
            Self::SlhDsa128s | Self::SlhDsa128f => "NIST FIPS 205",
        }
    }

    pub const fn size_assumption(self) -> &'static str {
        match self {
            Self::EcdsaSecp256k1 => "common 71-byte DER signature plus one sighash byte",
            Self::SchnorrSecp256k1 => "64-byte BIP340 signature with SIGHASH_DEFAULT",
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => {
                "exact FIPS signature and public-key sizes; no extra Bitcoin sighash byte"
            }
            Self::SlhDsa128s | Self::SlhDsa128f => {
                "exact FIPS signature and public-key sizes; no extra Bitcoin sighash byte"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDisclosure {
    /// A fixed-size hash or commitment is stored in the output; the key is
    /// revealed only when spending.
    CommitUntilSpend { commitment_bytes: u64 },
    /// The complete public key is stored in the output.
    PublicKeyInOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationPlacement {
    Witness,
    Stripped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExperimentManifest {
    pub signature_checks: u64,
    pub revealed_public_keys: u64,
    pub key_disclosure: KeyDisclosure,
    pub authorization_placement: AuthorizationPlacement,
}

impl ExperimentManifest {
    pub fn validate(self) -> Result<Self, ResearchModelError> {
        if self.revealed_public_keys > self.signature_checks {
            return Err(ResearchModelError::MoreKeysThanSignatureChecks);
        }
        Ok(self)
    }

    pub fn canonical_description(self) -> String {
        let disclosure = match self.key_disclosure {
            KeyDisclosure::CommitUntilSpend { commitment_bytes } => {
                format!("commit:{commitment_bytes}")
            }
            KeyDisclosure::PublicKeyInOutput => "output".to_owned(),
        };
        let placement = match self.authorization_placement {
            AuthorizationPlacement::Witness => "witness",
            AuthorizationPlacement::Stripped => "stripped",
        };
        format!(
            "{RESEARCH_MODEL_VERSION};checks={};keys={};disclosure={disclosure};placement={placement}",
            self.signature_checks, self.revealed_public_keys
        )
    }

    pub fn manifest_id(self) -> [u8; 32] {
        bitcrab_common::types::hash::hash256(self.canonical_description().as_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationProjection {
    pub scheme: SignatureScheme,
    pub signature_bytes: u64,
    pub public_key_bytes: u64,
    pub output_commitment_bytes: u64,
    pub total_authorization_bytes: u64,
    pub authorization_weight: u64,
    pub virtual_bytes: u64,
}

impl AuthorizationProjection {
    pub fn ratio_to(self, baseline: Self) -> f64 {
        if baseline.authorization_weight == 0 {
            return 0.0;
        }
        self.authorization_weight as f64 / baseline.authorization_weight as f64
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResearchModelError {
    #[error("revealed public keys cannot exceed signature checks")]
    MoreKeysThanSignatureChecks,
    #[error("modeled byte count overflowed u64")]
    ByteCountOverflow,
}

pub fn project_authorization(
    manifest: ExperimentManifest,
    scheme: SignatureScheme,
) -> Result<AuthorizationProjection, ResearchModelError> {
    let manifest = manifest.validate()?;
    let signature_bytes = checked_mul(manifest.signature_checks, scheme.signature_bytes())?;
    let public_key_bytes = checked_mul(manifest.revealed_public_keys, scheme.public_key_bytes())?;
    let (spend_public_key_bytes, output_commitment_bytes) = match manifest.key_disclosure {
        KeyDisclosure::CommitUntilSpend { commitment_bytes } => (
            public_key_bytes,
            checked_mul(manifest.revealed_public_keys, commitment_bytes)?,
        ),
        KeyDisclosure::PublicKeyInOutput => (0, public_key_bytes),
    };

    let spend_bytes = checked_add(signature_bytes, spend_public_key_bytes)?;
    let total_authorization_bytes = checked_add(spend_bytes, output_commitment_bytes)?;
    let spend_weight = match manifest.authorization_placement {
        AuthorizationPlacement::Witness => spend_bytes,
        AuthorizationPlacement::Stripped => checked_mul(spend_bytes, 4)?,
    };
    let authorization_weight = checked_add(spend_weight, checked_mul(output_commitment_bytes, 4)?)?;

    Ok(AuthorizationProjection {
        scheme,
        signature_bytes,
        public_key_bytes,
        output_commitment_bytes,
        total_authorization_bytes,
        authorization_weight,
        virtual_bytes: authorization_weight.div_ceil(4),
    })
}

fn checked_add(a: u64, b: u64) -> Result<u64, ResearchModelError> {
    a.checked_add(b)
        .ok_or(ResearchModelError::ByteCountOverflow)
}

fn checked_mul(a: u64, b: u64) -> Result<u64, ResearchModelError> {
    a.checked_mul(b)
        .ok_or(ResearchModelError::ByteCountOverflow)
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(placement: AuthorizationPlacement) -> ExperimentManifest {
        ExperimentManifest {
            signature_checks: 2,
            revealed_public_keys: 2,
            key_disclosure: KeyDisclosure::CommitUntilSpend {
                commitment_bytes: 32,
            },
            authorization_placement: placement,
        }
    }

    #[test]
    fn ml_dsa_projection_uses_fips_sizes() {
        let projection = project_authorization(
            manifest(AuthorizationPlacement::Witness),
            SignatureScheme::MlDsa44,
        )
        .unwrap();

        assert_eq!(projection.signature_bytes, 4_840);
        assert_eq!(projection.public_key_bytes, 2_624);
        assert_eq!(projection.output_commitment_bytes, 64);
        assert_eq!(projection.authorization_weight, 7_720);
    }

    #[test]
    fn stripped_authorization_costs_four_weight_per_spend_byte() {
        let witness = project_authorization(
            manifest(AuthorizationPlacement::Witness),
            SignatureScheme::MlDsa44,
        )
        .unwrap();
        let stripped = project_authorization(
            manifest(AuthorizationPlacement::Stripped),
            SignatureScheme::MlDsa44,
        )
        .unwrap();

        assert!(stripped.authorization_weight > witness.authorization_weight);
        assert_eq!(
            stripped.output_commitment_bytes,
            witness.output_commitment_bytes
        );
    }

    #[test]
    fn manifest_rejects_more_revealed_keys_than_checks() {
        let invalid = ExperimentManifest {
            signature_checks: 1,
            revealed_public_keys: 2,
            key_disclosure: KeyDisclosure::PublicKeyInOutput,
            authorization_placement: AuthorizationPlacement::Witness,
        };

        assert_eq!(
            project_authorization(invalid, SignatureScheme::EcdsaSecp256k1),
            Err(ResearchModelError::MoreKeysThanSignatureChecks)
        );
    }

    #[test]
    fn manifest_id_changes_when_an_assumption_changes() {
        let witness = manifest(AuthorizationPlacement::Witness);
        let stripped = manifest(AuthorizationPlacement::Stripped);

        assert_ne!(witness.manifest_id(), stripped.manifest_id());
        assert_eq!(witness.manifest_id(), witness.manifest_id());
    }

    #[test]
    fn public_key_in_output_is_not_counted_twice() {
        let manifest = ExperimentManifest {
            signature_checks: 1,
            revealed_public_keys: 1,
            key_disclosure: KeyDisclosure::PublicKeyInOutput,
            authorization_placement: AuthorizationPlacement::Witness,
        };

        let projection = project_authorization(manifest, SignatureScheme::MlDsa44).unwrap();

        assert_eq!(projection.total_authorization_bytes, 2_420 + 1_312);
        assert_eq!(projection.authorization_weight, 2_420 + (1_312 * 4));
    }
}
