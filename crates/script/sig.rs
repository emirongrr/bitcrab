//! Signature and public key encoding rules.
//!
//! Bitcoin Core: `IsValidSignatureEncoding()`, `IsLowDERSignature()`,
//! `IsDefinedHashtypeSignature()` and `IsCompressedOrUncompressedPubKey()` in
//! `src/script/interpreter.cpp`.
//!
//! These are *encoding* rules, checked before any elliptic curve work. They
//! exist because OpenSSL historically accepted several DER-ish encodings of the
//! same signature, which made transactions malleable (BIP 62 / BIP 66).

use crate::error::{ScriptError, ScriptResult};
use crate::flags::VerifyFlags;

/// Signature hash types.
///
/// Bitcoin Core: `SIGHASH_*` in `src/script/interpreter.h`.
pub const SIGHASH_ALL: u8 = 1;
pub const SIGHASH_NONE: u8 = 2;
pub const SIGHASH_SINGLE: u8 = 3;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// Half the secp256k1 group order, as big-endian bytes.
///
/// A signature is "low S" when `S <= n/2`. Since `(r, s)` and `(r, n-s)` are
/// both valid, requiring the lower one removes that malleability.
const HALF_CURVE_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// Strict DER validation of a signature *including* its trailing hash-type byte.
///
/// Bitcoin Core: `IsValidSignatureEncoding()`. Reproduced structurally rather
/// than delegating to a DER parser, because the rule is about the exact byte
/// layout, not about what a lenient parser can recover.
///
/// Format: `0x30 <total-len> 0x02 <R-len> <R> 0x02 <S-len> <S> <hashtype>`
pub fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Minimum: 30 06 02 01 00 02 01 00 [hashtype] = 9 bytes.
    // Maximum: 73 bytes.
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }

    if sig[0] != 0x30 {
        return false;
    }
    // Length byte must cover everything except the leading two bytes and the
    // trailing hash type.
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }

    let len_r = sig[3] as usize;
    // R's length must leave room for S's header and body.
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != sig.len() {
        return false;
    }

    // R
    if sig[2] != 0x02 {
        return false;
    }
    if len_r == 0 {
        return false;
    }
    if sig[4] & 0x80 != 0 {
        return false; // negative
    }
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false; // non-minimal padding
    }

    // S
    if sig[len_r + 4] != 0x02 {
        return false;
    }
    if len_s == 0 {
        return false;
    }
    if sig[len_r + 6] & 0x80 != 0 {
        return false; // negative
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false; // non-minimal padding
    }

    true
}

/// True if the signature's S value is in the lower half of the curve order.
///
/// Bitcoin Core: `IsLowDERSignature()`.
pub fn is_low_der_signature(sig: &[u8]) -> bool {
    if !is_valid_signature_encoding(sig) {
        return false;
    }

    let len_r = sig[3] as usize;
    let len_s = sig[5 + len_r] as usize;
    let s = &sig[len_r + 6..len_r + 6 + len_s];

    // Strip DER's leading zero padding to get the raw big-endian magnitude.
    let s = match s.first() {
        Some(0x00) if s.len() > 1 => &s[1..],
        _ => s,
    };

    if s.len() > 32 {
        return false;
    }

    let mut padded = [0u8; 32];
    padded[32 - s.len()..].copy_from_slice(s);
    padded <= HALF_CURVE_ORDER
}

/// True if the trailing hash-type byte is one Bitcoin defines.
///
/// Bitcoin Core: `IsDefinedHashtypeSignature()`.
pub fn is_defined_hashtype(sig: &[u8]) -> bool {
    let Some(&hashtype) = sig.last() else {
        return false;
    };
    let base = hashtype & !SIGHASH_ANYONECANPAY;
    (SIGHASH_ALL..=SIGHASH_SINGLE).contains(&base)
}

/// True for a 33-byte compressed or 65-byte uncompressed SEC public key.
///
/// Bitcoin Core: `IsCompressedOrUncompressedPubKey()`.
pub fn is_compressed_or_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    match pubkey.len() {
        33 => pubkey[0] == 0x02 || pubkey[0] == 0x03,
        65 => pubkey[0] == 0x04,
        _ => false,
    }
}

/// True for a 33-byte compressed SEC public key.
///
/// Bitcoin Core: `IsCompressedPubKey()`.
pub fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

/// Apply the flag-gated signature encoding rules.
///
/// Bitcoin Core: `CheckSignatureEncoding()`. An empty signature always passes:
/// it is the canonical way to say "this check is expected to fail", and
/// `NULLFAIL` is what turns a *non-empty* failing signature into an error.
pub fn check_signature_encoding(sig: &[u8], flags: VerifyFlags) -> ScriptResult<()> {
    if sig.is_empty() {
        return Ok(());
    }

    if (flags.contains(VerifyFlags::DERSIG)
        || flags.contains(VerifyFlags::LOW_S)
        || flags.contains(VerifyFlags::STRICTENC))
        && !is_valid_signature_encoding(sig)
    {
        return Err(ScriptError::SigDer);
    }
    if flags.contains(VerifyFlags::LOW_S) && !is_low_der_signature(sig) {
        return Err(ScriptError::SigHighS);
    }
    if flags.contains(VerifyFlags::STRICTENC) && !is_defined_hashtype(sig) {
        return Err(ScriptError::SigHashType);
    }

    Ok(())
}

/// Apply the flag-gated public key encoding rules.
///
/// Bitcoin Core: `CheckPubKeyEncoding()`.
pub fn check_pubkey_encoding(
    pubkey: &[u8],
    flags: VerifyFlags,
    is_witness_v0: bool,
) -> ScriptResult<()> {
    if flags.contains(VerifyFlags::STRICTENC) && !is_compressed_or_uncompressed_pubkey(pubkey) {
        return Err(ScriptError::PubkeyType);
    }
    // Only compressed keys are allowed in witness v0 (BIP 143), and only when
    // the flag is on — uncompressed keys there are non-standard, not invalid.
    if flags.contains(VerifyFlags::WITNESS_PUBKEYTYPE)
        && is_witness_v0
        && !is_compressed_pubkey(pubkey)
    {
        return Err(ScriptError::WitnessPubkeyType);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid low-S signature with SIGHASH_ALL.
    fn valid_sig() -> Vec<u8> {
        let mut sig = vec![0x30, 0x44, 0x02, 0x20];
        sig.extend_from_slice(&[0x11; 32]); // R
        sig.extend_from_slice(&[0x02, 0x20]);
        sig.extend_from_slice(&[0x22; 32]); // S (well below n/2)
        sig.push(SIGHASH_ALL);
        sig
    }

    #[test]
    fn accepts_a_well_formed_signature() {
        let sig = valid_sig();
        assert!(is_valid_signature_encoding(&sig));
        assert!(is_low_der_signature(&sig));
        assert!(is_defined_hashtype(&sig));
    }

    #[test]
    fn rejects_structural_der_violations() {
        let base = valid_sig();

        let mut wrong_tag = base.clone();
        wrong_tag[0] = 0x31;
        assert!(!is_valid_signature_encoding(&wrong_tag));

        let mut wrong_len = base.clone();
        wrong_len[1] = 0x43;
        assert!(!is_valid_signature_encoding(&wrong_len));

        let mut not_integer = base.clone();
        not_integer[2] = 0x03;
        assert!(!is_valid_signature_encoding(&not_integer));

        // Too short / too long.
        assert!(!is_valid_signature_encoding(&base[..8]));
        assert!(!is_valid_signature_encoding(&[0x30; 74]));
        assert!(!is_valid_signature_encoding(&[]));
    }

    #[test]
    fn rejects_negative_and_non_minimal_integers() {
        // R with the high bit set is a negative DER integer.
        let mut negative_r = valid_sig();
        negative_r[4] = 0x80;
        assert!(!is_valid_signature_encoding(&negative_r));

        // R padded with a leading zero that is not needed.
        let mut sig = vec![0x30, 0x44, 0x02, 0x20, 0x00, 0x01];
        sig.extend_from_slice(&[0x11; 30]);
        sig.extend_from_slice(&[0x02, 0x20]);
        sig.extend_from_slice(&[0x22; 32]);
        sig.push(SIGHASH_ALL);
        assert!(!is_valid_signature_encoding(&sig));
    }

    #[test]
    fn detects_high_s_values() {
        // S = n/2 exactly is still low.
        let mut at_limit = vec![0x30, 0x44, 0x02, 0x20];
        at_limit.extend_from_slice(&[0x11; 32]);
        at_limit.extend_from_slice(&[0x02, 0x20]);
        at_limit.extend_from_slice(&HALF_CURVE_ORDER);
        at_limit.push(SIGHASH_ALL);
        assert!(is_low_der_signature(&at_limit));

        // One above the limit is high.
        let mut above = at_limit.clone();
        let s_start = 4 + 32 + 2;
        above[s_start + 31] += 1;
        assert!(!is_low_der_signature(&above));
    }

    #[test]
    fn hashtype_must_be_one_bitcoin_defines() {
        for hashtype in [
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        ] {
            let mut sig = valid_sig();
            *sig.last_mut().unwrap() = hashtype;
            assert!(
                is_defined_hashtype(&sig),
                "{:#04x} should be valid",
                hashtype
            );
        }

        for hashtype in [0x00, 0x04, 0x05, 0x84] {
            let mut sig = valid_sig();
            *sig.last_mut().unwrap() = hashtype;
            assert!(
                !is_defined_hashtype(&sig),
                "{:#04x} should be rejected",
                hashtype
            );
        }
    }

    #[test]
    fn pubkey_encodings() {
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&[0x11; 32]);
        assert!(is_compressed_or_uncompressed_pubkey(&compressed));
        assert!(is_compressed_pubkey(&compressed));

        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0x11; 64]);
        assert!(is_compressed_or_uncompressed_pubkey(&uncompressed));
        assert!(!is_compressed_pubkey(&uncompressed));

        // Wrong prefix and wrong length.
        let mut bad_prefix = vec![0x05];
        bad_prefix.extend_from_slice(&[0x11; 32]);
        assert!(!is_compressed_or_uncompressed_pubkey(&bad_prefix));
        assert!(!is_compressed_or_uncompressed_pubkey(&[0x02; 10]));
    }

    #[test]
    fn empty_signature_bypasses_encoding_checks() {
        // An empty signature is how a script says "expect this to fail"; the
        // encoding rules must not turn it into a hard error.
        let all_flags = VerifyFlags::DERSIG | VerifyFlags::LOW_S | VerifyFlags::STRICTENC;
        assert_eq!(check_signature_encoding(&[], all_flags), Ok(()));
    }

    #[test]
    fn encoding_checks_are_flag_gated() {
        // S must stay a *valid* positive DER integer, or the DER check would
        // fire first and mask the low-S rule being tested. 0x7fff..ff is
        // positive (high bit clear) and comfortably above n/2.
        let mut high_s = vec![0x30, 0x44, 0x02, 0x20];
        high_s.extend_from_slice(&[0x11; 32]);
        high_s.extend_from_slice(&[0x02, 0x20, 0x7f]);
        high_s.extend_from_slice(&[0xff; 31]);
        high_s.push(SIGHASH_ALL);

        assert!(
            is_valid_signature_encoding(&high_s),
            "fixture must be DER-valid so only the low-S rule can reject it"
        );

        assert_eq!(check_signature_encoding(&high_s, VerifyFlags::NONE), Ok(()));
        assert_eq!(
            check_signature_encoding(&high_s, VerifyFlags::LOW_S),
            Err(ScriptError::SigHighS)
        );
    }
}
