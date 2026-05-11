//! Internal helpers: I2OSP, length-prefixed concatenation, context strings.
//!
//! The context string and per-hash DSTs for our single supported ciphersuite
//! (POPRF over ristretto255-SHA512) are compile-time constants. This avoids
//! per-call `Vec<u8>` allocations on every protocol invocation.

use alloc::vec::Vec;

use crate::error::Error;

/// Maximum permitted byte length of a length-prefixed input or info value.
///
/// RFC 9497 §5.1: "Application inputs, expressed as PrivateInput or
/// PublicInput values, MUST be smaller than 2^16 - 1 bytes in length."
/// Equivalently, `len <= 2^16 - 2`. All `input` and `info` parameters are
/// length-prefixed with `I2OSP(_, 2)` in `Blind`, `Finalize`,
/// `BlindEvaluate`, and `Evaluate`.
pub(crate) const MAX_LP_LEN: usize = (1usize << 16) - 2;

/// Reject byte strings that exceed [`MAX_LP_LEN`] (RFC 9497 §5.1).
///
/// Returning [`Error::InputTooLong`] up-front prevents the `I2OSP(_, 2)`
/// length prefix from being truncated, which would otherwise corrupt the
/// `Finalize` transcript and silently desynchronise the client and server.
#[inline]
pub(crate) fn check_lp_len(buf: &[u8]) -> Result<(), Error> {
    if buf.len() > MAX_LP_LEN {
        Err(Error::InputTooLong)
    } else {
        Ok(())
    }
}

/// `I2OSP(x, 1)`.
#[inline]
pub(crate) const fn i2osp_1(x: u8) -> [u8; 1] {
    [x]
}

/// `I2OSP(x, 2)` — big-endian 2-byte encoding.
///
/// Callers MUST ensure `x <= u16::MAX` (RFC 9497 §5.1 cap); every public
/// entry point that feeds a length-prefixed value into this helper calls
/// [`check_lp_len`] first, so reaching the `debug_assert!` in a release
/// build indicates an internal invariant violation upstream.
#[inline]
pub(crate) fn i2osp_2(x: usize) -> [u8; 2] {
    debug_assert!(x <= u16::MAX as usize, "I2OSP(x, 2) overflow");
    (x as u16).to_be_bytes()
}

/// Append `I2OSP(buf.len(), 2) || buf` to `out`.
#[inline]
pub(crate) fn append_lp(out: &mut Vec<u8>, buf: &[u8]) {
    out.extend_from_slice(&i2osp_2(buf.len()));
    out.extend_from_slice(buf);
}

// ── compile-time context string + DSTs (RFC 9497 §3.1, §4) ────────────────────
//
// For POPRF/ristretto255-SHA512 the context string is fixed:
//   "OPRFV1-" || I2OSP(MODE_POPRF, 1) || "-" || "ristretto255-SHA512"
// and the three per-hash DSTs are simple `<label> || contextString` prefixes.
// All four are exposed to the rest of the crate as `&'static [u8]` so no
// allocation is ever required during protocol execution.

/// `"OPRFV1-" || 0x02 || "-" || "ristretto255-SHA512"` (RFC 9497 §3.1).
///
/// Kept as a named constant so the test below can sanity-check the
/// DST constants against their textbook construction. The runtime code
/// never consumes the bare context string — only the prefixed DSTs.
#[cfg(test)]
const CONTEXT_STRING: &[u8] = b"OPRFV1-\x02-ristretto255-SHA512";

/// `"HashToGroup-" || contextString` (RFC 9497 §4).
pub(crate) const HASH_TO_GROUP_DST: &[u8] = b"HashToGroup-OPRFV1-\x02-ristretto255-SHA512";

/// `"HashToScalar-" || contextString` (RFC 9497 §4).
pub(crate) const HASH_TO_SCALAR_DST: &[u8] = b"HashToScalar-OPRFV1-\x02-ristretto255-SHA512";

/// `"DeriveKeyPair" || contextString` (RFC 9497 §3.2.1).
pub(crate) const DERIVE_KEY_PAIR_DST: &[u8] = b"DeriveKeyPairOPRFV1-\x02-ristretto255-SHA512";

/// `"Seed-" || contextString` — used as the seed-DST in `ComputeComposites`
/// (RFC 9497 §2.2.1) when constructing DLEQ proof transcripts.
pub(crate) const SEED_DST: &[u8] = b"Seed-OPRFV1-\x02-ristretto255-SHA512";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MODE_POPRF, SUITE_ID};

    /// Ensure the compile-time constants exactly equal what the textbook
    /// formula would produce; guards against typos in the const literals.
    #[test]
    fn context_string_constants_match_formula() {
        let mut want_ctx = Vec::with_capacity(7 + 1 + 1 + SUITE_ID.len());
        want_ctx.extend_from_slice(b"OPRFV1-");
        want_ctx.push(MODE_POPRF);
        want_ctx.extend_from_slice(b"-");
        want_ctx.extend_from_slice(SUITE_ID.as_bytes());
        assert_eq!(CONTEXT_STRING, want_ctx.as_slice());

        let want_h2g: Vec<u8> = [b"HashToGroup-".as_ref(), &want_ctx].concat();
        assert_eq!(HASH_TO_GROUP_DST, want_h2g.as_slice());

        let want_h2s: Vec<u8> = [b"HashToScalar-".as_ref(), &want_ctx].concat();
        assert_eq!(HASH_TO_SCALAR_DST, want_h2s.as_slice());

        let want_dkp: Vec<u8> = [b"DeriveKeyPair".as_ref(), &want_ctx].concat();
        assert_eq!(DERIVE_KEY_PAIR_DST, want_dkp.as_slice());

        let want_seed: Vec<u8> = [b"Seed-".as_ref(), &want_ctx].concat();
        assert_eq!(SEED_DST, want_seed.as_slice());
    }
}
