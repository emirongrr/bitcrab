//! Script evaluation errors.
//!
//! Mirrors `ScriptError_t` in Bitcoin Core `src/script/script_error.h`. Keeping
//! the variants one-to-one matters for differential testing: when the native
//! engine and `libbitcoinconsensus` disagree, the specific error tells you
//! *which* rule diverged rather than just "it failed".

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScriptError {
    #[error("script evaluated to false")]
    EvalFalse,
    #[error("OP_RETURN encountered")]
    OpReturn,

    // Max sizes
    #[error("script is larger than MAX_SCRIPT_SIZE")]
    ScriptSize,
    #[error("push value is larger than MAX_SCRIPT_ELEMENT_SIZE")]
    PushSize,
    #[error("operation count exceeded MAX_OPS_PER_SCRIPT")]
    OpCount,
    #[error("stack size exceeded MAX_STACK_SIZE")]
    StackSize,
    #[error("public key count out of range for CHECKMULTISIG")]
    PubkeyCount,
    #[error("signature count out of range for CHECKMULTISIG")]
    SigCount,

    // Failed verify operations
    #[error("OP_VERIFY failed")]
    Verify,
    #[error("OP_EQUALVERIFY failed")]
    EqualVerify,
    #[error("OP_CHECKMULTISIGVERIFY failed")]
    CheckMultisigVerify,
    #[error("OP_CHECKSIGVERIFY failed")]
    CheckSigVerify,
    #[error("OP_NUMEQUALVERIFY failed")]
    NumEqualVerify,

    // Logical/Format/Canonical errors
    #[error("malformed push operation")]
    BadOpcode,
    #[error("disabled opcode")]
    DisabledOpcode,
    #[error("operation on an empty stack")]
    InvalidStackOperation,
    #[error("OP_ELSE/OP_ENDIF without a matching OP_IF")]
    InvalidAltstackOperation,
    #[error("unbalanced conditional")]
    UnbalancedConditional,

    // CHECKLOCKTIMEVERIFY / CHECKSEQUENCEVERIFY
    #[error("negative locktime")]
    NegativeLocktime,
    #[error("locktime requirement not satisfied")]
    UnsatisfiedLocktime,

    // BIP62
    #[error("signature hash type is invalid")]
    SigHashType,
    #[error("non-canonical DER signature")]
    SigDer,
    #[error("data push larger than necessary")]
    MinimalData,
    #[error("only push operators allowed in signature scripts")]
    SigPushOnly,
    #[error("non-canonical signature: S value is unnecessarily high")]
    SigHighS,
    #[error("dummy CHECKMULTISIG argument must be zero")]
    SigNullDummy,
    #[error("public key is neither compressed nor uncompressed")]
    PubkeyType,
    #[error("stack must contain exactly one item after execution")]
    CleanStack,
    #[error("OP_IF/OP_NOTIF argument must be minimal")]
    MinimalIf,
    #[error("signature must be zero for failed CHECK(MULTI)SIG operation")]
    SigNullFail,

    // Softfork safeness
    #[error("NOPx reserved for soft-fork upgrades")]
    DiscourageUpgradableNops,
    #[error("witness version reserved for soft-fork upgrades")]
    DiscourageUpgradableWitnessProgram,

    // SegWit
    #[error("witness program has incorrect length")]
    WitnessProgramWrongLength,
    #[error("witness program was passed an empty witness")]
    WitnessProgramWitnessEmpty,
    #[error("witness program hash mismatch")]
    WitnessProgramMismatch,
    #[error("witness requires empty scriptSig")]
    WitnessMalleated,
    #[error("witness requires only-redeemscript scriptSig")]
    WitnessMalleatedP2sh,
    #[error("witness provided for non-witness script")]
    WitnessUnexpected,
    #[error("using non-compressed public key in a witness program")]
    WitnessPubkeyType,

    #[error("OP_CODESEPARATOR/FindAndDelete in a scriptCode covered by a signature")]
    OpCodeseparator,
    #[error("signature check failed")]
    SigFindAndDelete,

    // Taproot (BIP 341 / BIP 342)
    #[error("taproot control block has an invalid size")]
    TaprootWrongControlSize,
    #[error("taproot leaf version is reserved for soft-fork upgrades")]
    DiscourageUpgradableTaprootVersion,
    #[error("OP_SUCCESSx reserved for soft-fork upgrades")]
    DiscourageOpSuccess,
    #[error("public key type reserved for soft-fork upgrades")]
    DiscourageUpgradablePubkeyType,
    #[error("OP_CHECKMULTISIG(VERIFY) is disabled in tapscript")]
    TapscriptCheckMultisig,
    #[error("schnorr signature has an invalid size")]
    SchnorrSigSize,
    #[error("schnorr signature uses an invalid hash type")]
    SchnorrSigHashType,
    #[error("schnorr signature is malformed")]
    SchnorrSig,
    #[error("schnorr public key is malformed")]
    SchnorrSigPubkey,
    #[error("tapscript exceeded its signature validation weight budget")]
    TapscriptValidationWeight,
    #[error("OP_CHECKMULTISIG in tapscript must use OP_CHECKSIGADD")]
    TapscriptMinimalIf,

    #[error("unknown error")]
    UnknownError,
}

pub type ScriptResult<T> = Result<T, ScriptError>;
