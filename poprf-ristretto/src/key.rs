//! Key types and key generation (RFC 9497 §3.2).
//!
//! [`SecretKey`] and [`PublicKey`] are opaque newtypes around the underlying
//! curve scalar / point. They expose only `from_bytes` / `to_bytes` of the
//! canonical 32-byte wire format defined in RFC 9497 §4.1 (`Ns = Ne = 32`).

use alloc::vec::Vec;
use core::fmt;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::group;
use crate::util::{DERIVE_KEY_PAIR_DST, check_lp_len, i2osp_1, i2osp_2};

// ── SecretKey ─────────────────────────────────────────────────────────────────

/// POPRF server secret key `skS` (RFC 9497 §3.2).
///
/// # Security
///
/// This is **server-secret** material:
///
/// * MUST be sampled from a CSPRNG (via [`generate_key_pair`]) or derived from
///   a CSPRNG seed (via [`derive_key_pair`]).
/// * MUST NOT be logged, transmitted, or stored in cleartext.
/// * Should be kept in memory for the shortest time possible. The inner
///   scalar is wiped on drop via `ZeroizeOnDrop`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) Scalar);

impl SecretKey {
    /// Wire-format length: `Ns = 32` bytes.
    pub const LEN: usize = group::SCALAR_LEN;

    /// Serialize as `SerializeScalar(skS)` — 32 bytes, little-endian canonical.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        group::serialize_scalar_array(&self.0)
    }

    /// Deserialize from `SerializeScalar` form. Rejects non-canonical or zero
    /// scalars; RFC 9497 implicitly forbids `skS = 0` since `pkS = 0·G = O`
    /// would make `BlindEvaluate` trivially insecure.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let s = group::deserialize_scalar(buf)?;
        if bool::from(s.ct_eq(&Scalar::ZERO)) {
            return Err(Error::InputValidation);
        }
        Ok(Self(s))
    }

    /// Derive the corresponding [`PublicKey`].
    #[inline]
    #[must_use = "deriving a public key without using it performs a base-point \
                  scalar multiplication for nothing"]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(group::scalar_mul_gen(&self.0))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

// ── PublicKey ─────────────────────────────────────────────────────────────────

/// POPRF server public key `pkS = skS·G` (RFC 9497 §3.2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub(crate) RistrettoPoint);

impl PublicKey {
    /// Wire-format length: `Ne = 32` bytes.
    pub const LEN: usize = group::ELEMENT_LEN;

    /// Serialize as `SerializeElement(pkS)` — 32 bytes, canonical Ristretto
    /// compression.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        group::serialize_element_array(&self.0)
    }

    /// Deserialize from `SerializeElement` form. Rejects identity and
    /// non-canonical encodings (RFC 9497 §4.1, RFC 9496 §A.2).
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        Ok(Self(group::deserialize_element(buf)?))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        f.write_str("PublicKey(")?;
        for byte in &bytes {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

// ── Generation ────────────────────────────────────────────────────────────────

/// `GenerateKeyPair()` — RFC 9497 §3.2.
///
/// Returns `(skS, pkS)` sampled from `rng`.
#[inline]
#[must_use = "discarding a freshly-generated key pair consumes RNG output \
              for no reason"]
pub fn generate_key_pair<R: RngCore + CryptoRng>(rng: &mut R) -> (SecretKey, PublicKey) {
    let sk = SecretKey(group::random_scalar(rng));
    let pk = sk.public_key();
    (sk, pk)
}

/// `DeriveKeyPair(seed, info)` — RFC 9497 §3.2.1.
///
/// The `seed` MUST be 32 bytes from a CSPRNG. Returns
/// [`Error::DeriveKeyPair`] if all 256 counter-suffixed `HashToScalar`
/// invocations produce the zero scalar (negligible probability).
pub fn derive_key_pair(seed: &[u8; 32], info: &[u8]) -> Result<(SecretKey, PublicKey), Error> {
    // RFC 9497 §5.1: `info` is length-prefixed with two bytes in deriveInput.
    check_lp_len(info)?;
    let mut derive_input = Vec::with_capacity(32 + 2 + info.len());
    derive_input.extend_from_slice(seed);
    derive_input.extend_from_slice(&i2osp_2(info.len()));
    derive_input.extend_from_slice(info);

    for counter in 0u16..=255 {
        let counter_byte = i2osp_1(counter as u8);
        let sk = group::hash_to_scalar(&[&derive_input, &counter_byte], DERIVE_KEY_PAIR_DST);
        if !bool::from(group::scalar_is_zero(&sk)) {
            let sk = SecretKey(sk);
            let pk = sk.public_key();
            return Ok((sk, pk));
        }
    }
    Err(Error::DeriveKeyPair)
}

// ── serde ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
mod serde_impls {
    use super::{PublicKey, SecretKey};
    use crate::serde_util::{deser_fixed, ser_fixed};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for SecretKey {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            ser_fixed(&self.to_bytes(), s)
        }
    }
    impl<'de> Deserialize<'de> for SecretKey {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let bytes: [u8; Self::LEN] = deser_fixed::<{ Self::LEN }, _>(d)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }

    impl Serialize for PublicKey {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            ser_fixed(&self.to_bytes(), s)
        }
    }
    impl<'de> Deserialize<'de> for PublicKey {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let bytes: [u8; Self::LEN] = deser_fixed::<{ Self::LEN }, _>(d)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}
