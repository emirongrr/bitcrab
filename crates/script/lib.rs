//! Bitcoin Script engine.
//!
//! A native implementation of Bitcoin's script consensus rules — legacy, P2SH,
//! SegWit v0 and taproot — structured to
//! mirror Bitcoin Core's `src/script/` so the two can be compared rule by rule.
//! `libbitcoinconsensus` remains available behind the `core-reference` feature
//! of `bitcrab-consensus` as a differential-testing oracle, not as the
//! production path.
//!
//! Module map, and the Core file each one tracks:
//!
//! | module       | Bitcoin Core            |
//! |--------------|-------------------------|
//! | `opcode`     | `script.h` (opcodetype) |
//! | `num`        | `script.h` (CScriptNum) |
//! | `script_ops` | `script.cpp`            |
//! | `sig`        | `interpreter.cpp`       |
//! | `sighash`    | `interpreter.cpp`       |
//! | `taproot`    | `interpreter.cpp` (BIP 341/342) |
//! | `checker`    | `interpreter.h`         |
//! | `interpreter`| `interpreter.cpp`       |
//! | `flags`      | `interpreter.h`         |
//! | `error`      | `script_error.h`        |

pub mod checker;
pub mod error;
pub mod flags;
pub mod interpreter;
pub mod num;
pub mod opcode;
pub mod research;
pub mod script_ops;
pub mod sig;
pub mod sighash;
pub mod signature_experiment;
pub mod taproot;

#[cfg(test)]
mod taproot_tests;
#[cfg(test)]
mod tests;

pub use checker::{
    NullSignatureChecker, PrecomputedTransactionData, SigVersion, SignatureChecker,
    TransactionSignatureChecker,
};
pub use error::{ScriptError, ScriptResult};
pub use flags::VerifyFlags;
pub use interpreter::{eval_script, eval_script_with_data, verify_script};
pub use num::{cast_to_bool, ScriptNum};
pub use opcode::Opcode;
pub use sighash::{
    legacy_signature_hash, taproot_signature_hash, witness_v0_signature_hash, Bip143Cache,
    TaprootCache,
};
pub use taproot::ScriptExecutionData;

pub use research::{
    project_authorization, AuthorizationPlacement, AuthorizationProjection, ExperimentManifest,
    KeyDisclosure, ResearchModelError, SignatureScheme, RESEARCH_MODEL_VERSION,
};
pub use signature_experiment::{
    benchmark_signature_workload, ClassicSecp256k1Verifier, SignatureBenchmarkResult,
    SignatureExperimentError, SignatureExperimentVerifier, SignatureFamily, SignatureWorkItem,
};
