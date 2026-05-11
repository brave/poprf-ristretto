//! Ristretto255-SHA512 group operations (RFC 9497 §4.1).
//!
//! Internal module. Free functions operating directly on `curve25519_dalek`
//! types. The crate is monomorphic over the ristretto255-SHA512 ciphersuite
//! and exposes no curve types in its public API.

use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;
use subtle::{Choice, ConstantTimeEq};

use crate::error::Error;

/// Serialized length of a ristretto255 element (`Ne`).
pub(crate) const ELEMENT_LEN: usize = 32;

/// Serialized length of a ristretto255 scalar (`Ns`).
pub(crate) const SCALAR_LEN: usize = 32;

#[cfg_attr(feature = "fast-dleq", allow(dead_code))]
#[inline]
pub(crate) fn identity() -> RistrettoPoint {
    RistrettoPoint::identity()
}

#[inline]
pub(crate) fn generator() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

#[inline]
pub(crate) fn scalar_mul(scalar: &Scalar, element: &RistrettoPoint) -> RistrettoPoint {
    scalar * element
}

#[inline]
pub(crate) fn scalar_mul_gen(scalar: &Scalar) -> RistrettoPoint {
    scalar * RISTRETTO_BASEPOINT_POINT
}

#[inline]
pub(crate) fn element_add(a: &RistrettoPoint, b: &RistrettoPoint) -> RistrettoPoint {
    a + b
}

#[inline]
pub(crate) fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    a + b
}

#[inline]
pub(crate) fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    a - b
}

#[inline]
pub(crate) fn scalar_mul_scalar(a: &Scalar, b: &Scalar) -> Scalar {
    a * b
}

#[inline]
pub(crate) fn scalar_invert(scalar: &Scalar) -> Scalar {
    scalar.invert()
}

#[inline]
pub(crate) fn scalar_is_zero(scalar: &Scalar) -> Choice {
    scalar.ct_eq(&Scalar::ZERO)
}

#[inline]
pub(crate) fn is_identity(element: &RistrettoPoint) -> Choice {
    element.ct_eq(&RistrettoPoint::identity())
}

/// `HashToGroup(input, dst)` — RFC 9497 §4.1 / RFC 9380 §4.
pub(crate) fn hash_to_group(inputs: &[&[u8]], dst: &[u8]) -> RistrettoPoint {
    let mut uniform_bytes = [0u8; 64];
    let dsts = [dst];
    let mut expander = <ExpandMsgXmd<Sha512> as ExpandMsg<'_>>::expand_message(inputs, &dsts, 64)
        .expect("expand_message_xmd cannot fail with valid params");
    expander.fill_bytes(&mut uniform_bytes);
    RistrettoPoint::from_uniform_bytes(&uniform_bytes)
}

/// `HashToScalar(input, dst)` — RFC 9497 §4.1 / RFC 9380 §4.
pub(crate) fn hash_to_scalar(inputs: &[&[u8]], dst: &[u8]) -> Scalar {
    let mut uniform_bytes = [0u8; 64];
    let dsts = [dst];
    let mut expander = <ExpandMsgXmd<Sha512> as ExpandMsg<'_>>::expand_message(inputs, &dsts, 64)
        .expect("expand_message_xmd cannot fail with valid params");
    expander.fill_bytes(&mut uniform_bytes);
    // RFC 9497 §4.1: interpret as 512-bit little-endian integer mod Order.
    Scalar::from_bytes_mod_order_wide(&uniform_bytes)
}

/// `RandomScalar()` — uniformly random nonzero scalar.
pub(crate) fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(rng);
        if !bool::from(s.ct_eq(&Scalar::ZERO)) {
            return s;
        }
    }
}

/// `SerializeElement(A)`.
#[inline]
pub(crate) fn serialize_element(element: &RistrettoPoint) -> Vec<u8> {
    element.compress().to_bytes().to_vec()
}

/// `SerializeElement(A)` to a fixed-size array.
#[inline]
pub(crate) fn serialize_element_array(element: &RistrettoPoint) -> [u8; ELEMENT_LEN] {
    element.compress().to_bytes()
}

/// `DeserializeElement(buf)`. Rejects identity and non-canonical encodings.
pub(crate) fn deserialize_element(buf: &[u8]) -> Result<RistrettoPoint, Error> {
    if buf.len() != ELEMENT_LEN {
        return Err(Error::Deserialize);
    }
    let mut arr = [0u8; ELEMENT_LEN];
    arr.copy_from_slice(buf);
    let point = CompressedRistretto(arr)
        .decompress()
        .ok_or(Error::Deserialize)?;
    if bool::from(point.ct_eq(&RistrettoPoint::identity())) {
        return Err(Error::InputValidation);
    }
    Ok(point)
}

/// `SerializeScalar(s)` to a fixed-size array.
#[inline]
pub(crate) fn serialize_scalar_array(scalar: &Scalar) -> [u8; SCALAR_LEN] {
    scalar.to_bytes()
}

/// `DeserializeScalar(buf)`. Rejects non-canonical values.
pub(crate) fn deserialize_scalar(buf: &[u8]) -> Result<Scalar, Error> {
    if buf.len() != SCALAR_LEN {
        return Err(Error::Deserialize);
    }
    let mut arr = [0u8; SCALAR_LEN];
    arr.copy_from_slice(buf);
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr)).ok_or(Error::Deserialize)
}

/// `Σ scalars[i] · points[i]` via vartime Pippenger MSM.
///
/// Only called (and compiled) when `fast-dleq` is enabled. Safe in the
/// DLEQ context because scalars are derived from a public Fiat-Shamir
/// transcript.
#[cfg(feature = "fast-dleq")]
pub(crate) fn msm(scalars: &[Scalar], points: &[RistrettoPoint]) -> RistrettoPoint {
    use curve25519_dalek::traits::VartimeMultiscalarMul;
    RistrettoPoint::vartime_multiscalar_mul(scalars.iter(), points.iter())
}
