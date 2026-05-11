//! Error type.

use core::fmt;

/// All errors raised by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Failed to deserialize a wire-format `Element`, `Scalar`, or `Proof`
    /// (length, encoding canonicality, or curve membership).
    Deserialize,
    /// A wire-decoded value was syntactically valid but rejected by
    /// protocol input validation: identity `Element` (RFC 9497 §4.1) or
    /// zero `SecretKey` scalar (RFC 9497 §3.2.1).
    InputValidation,
    /// `Blind` rejected an input that maps to the group identity element,
    /// or POPRF `Blind` produced a `tweakedKey` equal to the identity.
    InvalidInput,
    /// Batched API received slices of disagreeing length, or an empty batch.
    LengthMismatch,
    /// POPRF proof verification failed (RFC 9497 §3.3.3).
    Verify,
    /// POPRF `BlindEvaluate` could not invert because `skS + m == 0`
    /// (RFC 9497 §3.3.3 `InverseError`).
    Inverse,
    /// `DeriveKeyPair` exhausted its 256-iteration counter (RFC 9497 §3.2.1).
    DeriveKeyPair,
    /// `input` or `info` was `2^16 - 1` bytes or longer. RFC 9497 §5.1
    /// requires both to be smaller than `2^16 - 1` bytes (they are
    /// length-prefixed with two bytes throughout the protocol).
    InputTooLong,
    /// `finalize_batch` was called with `PoprfBlindState` entries whose
    /// `tweakedKey` values disagree. A batched POPRF finalize covers a
    /// single `(client, info)` tuple, so every state must share the same
    /// `tweakedKey` (RFC 9497 §3.3.3).
    InconsistentState,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::Deserialize => "deserialization failed",
            Error::InputValidation => "input validation failed",
            Error::InvalidInput => "invalid input",
            Error::LengthMismatch => "batched-API length mismatch",
            Error::Verify => "DLEQ proof verification failed",
            Error::Inverse => "inversion of zero scalar",
            Error::DeriveKeyPair => "DeriveKeyPair counter exhausted",
            Error::InputTooLong => "input or info length must be smaller than 2^16 - 1 bytes",
            Error::InconsistentState => "PoprfBlindState entries disagree on tweakedKey",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {}
