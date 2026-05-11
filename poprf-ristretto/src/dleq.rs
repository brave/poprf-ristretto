//! Discrete-Logarithm Equivalence (DLEQ) proofs (RFC 9497 §2.2).
//!
//! Internal except for [`Proof`], which is part of the protocol wire format.
//! [`PoprfClient`](crate::PoprfClient) and [`PoprfServer`](crate::PoprfServer)
//! generate and verify proofs internally.
//!
//! # Constant-time discipline
//!
//! Proof verification uses constant-time scalar equality
//! (`subtle::ConstantTimeEq`) so that a verifier cannot leak partial
//! information about the expected challenge. Composite computation under
//! `fast-dleq` uses vartime Pippenger MSM; this is safe because every
//! composite scalar is derived from a public Fiat-Shamir transcript.

use alloc::vec::Vec;
use core::fmt;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use digest::{FixedOutput, Update};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;
use subtle::ConstantTimeEq;

use crate::error::Error;
use crate::util::{HASH_TO_SCALAR_DST, SEED_DST, append_lp};
use crate::{group, util};

/// A DLEQ proof: the scalar pair `(c, s)` from RFC 9497 §2.2.1.
///
/// Wire format: `SerializeScalar(c) || SerializeScalar(s)` — 64 bytes.
///
/// A DLEQ proof contains no secret material: `c` is `HashToScalar` of a
/// public Fiat-Shamir transcript (RFC 9497 §2.2.1), and `s = r − c·k` is
/// transmitted in the clear to the verifier as part of the protocol. The
/// type therefore does not implement `ZeroizeOnDrop`.
#[derive(Clone)]
pub struct Proof {
    pub(crate) c: Scalar,
    pub(crate) s: Scalar,
}

impl Proof {
    /// Wire-format length: `2 * Ns = 64` bytes.
    pub const LEN: usize = 2 * group::SCALAR_LEN;

    /// Serialize as `SerializeScalar(c) || SerializeScalar(s)`.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..group::SCALAR_LEN].copy_from_slice(&group::serialize_scalar_array(&self.c));
        out[group::SCALAR_LEN..].copy_from_slice(&group::serialize_scalar_array(&self.s));
        out
    }

    /// Parse from wire format. Rejects non-canonical scalars and any input
    /// not exactly 64 bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() != Self::LEN {
            return Err(Error::Deserialize);
        }
        let c = group::deserialize_scalar(&buf[..group::SCALAR_LEN])?;
        let s = group::deserialize_scalar(&buf[group::SCALAR_LEN..])?;
        Ok(Self { c, s })
    }
}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        f.write_str("Proof(")?;
        for byte in &bytes {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
mod serde_impls {
    use super::Proof;
    use crate::serde_util::{deser_fixed, ser_fixed};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for Proof {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            ser_fixed(&self.to_bytes(), s)
        }
    }
    impl<'de> Deserialize<'de> for Proof {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let bytes: [u8; Self::LEN] = deser_fixed::<{ Self::LEN }, _>(d)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

// ── proof generation / verification (internal) ───────────────────────────────

/// `GenerateProof(k, A, B, C, D)` — RFC 9497 §2.2.1.
pub(crate) fn generate_proof<R: RngCore + CryptoRng>(
    rng: &mut R,
    k: &Scalar,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    c_list: &[RistrettoPoint],
    d_list: &[RistrettoPoint],
) -> Proof {
    let r = group::random_scalar(rng);
    generate_proof_with_r(k, a, b, c_list, d_list, &r)
}

/// `GenerateProof` with externally-supplied randomness (test vectors).
pub(crate) fn generate_proof_with_r(
    k: &Scalar,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    c_list: &[RistrettoPoint],
    d_list: &[RistrettoPoint],
    r: &Scalar,
) -> Proof {
    let (m_elt, z_elt) = compute_composites_fast(k, b, c_list, d_list);

    let t2 = group::scalar_mul(r, a);
    let t3 = group::scalar_mul(r, &m_elt);

    let bm = group::serialize_element(b);
    let a0 = group::serialize_element(&m_elt);
    let a1 = group::serialize_element(&z_elt);
    let a2 = group::serialize_element(&t2);
    let a3 = group::serialize_element(&t3);

    let mut transcript = Vec::with_capacity(
        2 * 5 + bm.len() + a0.len() + a1.len() + a2.len() + a3.len() + b"Challenge".len(),
    );
    append_lp(&mut transcript, &bm);
    append_lp(&mut transcript, &a0);
    append_lp(&mut transcript, &a1);
    append_lp(&mut transcript, &a2);
    append_lp(&mut transcript, &a3);
    transcript.extend_from_slice(b"Challenge");

    let c_chal = group::hash_to_scalar(&[&transcript], HASH_TO_SCALAR_DST);

    let ck = group::scalar_mul_scalar(&c_chal, k);
    let s = group::scalar_sub(r, &ck);

    Proof { c: c_chal, s }
}

/// `VerifyProof(A, B, C, D, proof)` — RFC 9497 §2.2.2.
pub(crate) fn verify_proof(
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    c_list: &[RistrettoPoint],
    d_list: &[RistrettoPoint],
    proof: &Proof,
) -> Result<(), Error> {
    let (m_elt, z_elt) = compute_composites(b, c_list, d_list);

    let s_a = group::scalar_mul(&proof.s, a);
    let c_b = group::scalar_mul(&proof.c, b);
    let t2 = group::element_add(&s_a, &c_b);

    let s_m = group::scalar_mul(&proof.s, &m_elt);
    let c_z = group::scalar_mul(&proof.c, &z_elt);
    let t3 = group::element_add(&s_m, &c_z);

    let bm = group::serialize_element(b);
    let a0 = group::serialize_element(&m_elt);
    let a1 = group::serialize_element(&z_elt);
    let a2 = group::serialize_element(&t2);
    let a3 = group::serialize_element(&t3);

    let mut transcript = Vec::with_capacity(
        2 * 5 + bm.len() + a0.len() + a1.len() + a2.len() + a3.len() + b"Challenge".len(),
    );
    append_lp(&mut transcript, &bm);
    append_lp(&mut transcript, &a0);
    append_lp(&mut transcript, &a1);
    append_lp(&mut transcript, &a2);
    append_lp(&mut transcript, &a3);
    transcript.extend_from_slice(b"Challenge");

    let expected_c = group::hash_to_scalar(&[&transcript], HASH_TO_SCALAR_DST);

    if bool::from(expected_c.ct_eq(&proof.c)) {
        Ok(())
    } else {
        Err(Error::Verify)
    }
}

// ── internal helpers ─────────────────────────────────────────────────────────

/// `ComputeCompositesFast` (RFC 9497 §2.2.1) — server path, uses `k`.
fn compute_composites_fast(
    k: &Scalar,
    b: &RistrettoPoint,
    c_list: &[RistrettoPoint],
    d_list: &[RistrettoPoint],
) -> (RistrettoPoint, RistrettoPoint) {
    let seed = composite_seed(b);
    let seed_len = util::i2osp_2(seed.len());
    let elem_len = util::i2osp_2(group::ELEMENT_LEN);

    #[cfg(feature = "fast-dleq")]
    let m = {
        let ds: Vec<Scalar> = c_list
            .iter()
            .zip(d_list.iter())
            .enumerate()
            .map(|(i, (ci, di_pt))| composite_di(&seed_len, &seed, i, &elem_len, ci, di_pt))
            .collect();
        group::msm(&ds, c_list)
    };

    #[cfg(not(feature = "fast-dleq"))]
    let m = {
        let mut acc = group::identity();
        for (i, (ci, di_pt)) in c_list.iter().zip(d_list.iter()).enumerate() {
            let di = composite_di(&seed_len, &seed, i, &elem_len, ci, di_pt);
            let term = group::scalar_mul(&di, ci);
            acc = group::element_add(&term, &acc);
        }
        acc
    };

    let z = group::scalar_mul(k, &m);
    (m, z)
}

/// `ComputeComposites` (RFC 9497 §2.2.2) — client path, no `k`.
fn compute_composites(
    b: &RistrettoPoint,
    c_list: &[RistrettoPoint],
    d_list: &[RistrettoPoint],
) -> (RistrettoPoint, RistrettoPoint) {
    let seed = composite_seed(b);
    let seed_len = util::i2osp_2(seed.len());
    let elem_len = util::i2osp_2(group::ELEMENT_LEN);

    #[cfg(feature = "fast-dleq")]
    {
        let ds: Vec<Scalar> = c_list
            .iter()
            .zip(d_list.iter())
            .enumerate()
            .map(|(i, (ci, di_pt))| composite_di(&seed_len, &seed, i, &elem_len, ci, di_pt))
            .collect();
        let m = group::msm(&ds, c_list);
        let z = group::msm(&ds, d_list);
        (m, z)
    }

    #[cfg(not(feature = "fast-dleq"))]
    {
        let mut m = group::identity();
        let mut z = group::identity();
        for (i, (ci, di_pt)) in c_list.iter().zip(d_list.iter()).enumerate() {
            let di = composite_di(&seed_len, &seed, i, &elem_len, ci, di_pt);
            let term_m = group::scalar_mul(&di, ci);
            let term_z = group::scalar_mul(&di, di_pt);
            m = group::element_add(&term_m, &m);
            z = group::element_add(&term_z, &z);
        }
        (m, z)
    }
}

fn composite_seed(b: &RistrettoPoint) -> Vec<u8> {
    let bm = group::serialize_element(b);
    let mut transcript = Vec::with_capacity(2 + bm.len() + 2 + SEED_DST.len());
    append_lp(&mut transcript, &bm);
    append_lp(&mut transcript, SEED_DST);

    let mut hasher = Sha512::default();
    Update::update(&mut hasher, &transcript);
    let digest = FixedOutput::finalize_fixed(hasher);
    digest[..].to_vec()
}

/// Per-element scalar `dᵢ` (RFC 9497 §2.2.1).
fn composite_di(
    seed_len: &[u8; 2],
    seed: &[u8],
    i: usize,
    elem_len: &[u8; 2],
    ci: &RistrettoPoint,
    di_pt: &RistrettoPoint,
) -> Scalar {
    let ci_bytes = group::serialize_element(ci);
    let di_bytes = group::serialize_element(di_pt);
    let i_bytes = util::i2osp_2(i);

    let inputs: [&[u8]; 8] = [
        seed_len,
        seed,
        &i_bytes,
        elem_len,
        &ci_bytes,
        elem_len,
        &di_bytes,
        b"Composite",
    ];
    group::hash_to_scalar(&inputs, HASH_TO_SCALAR_DST)
}
