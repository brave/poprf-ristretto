//! POPRF protocol (see: RFC 9497 §3.3.3).
//! https://www.rfc-editor.org/rfc/rfc9497.txt

use alloc::vec::Vec;
use core::fmt;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use digest::{FixedOutput, Update};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::dleq::{Proof, generate_proof, generate_proof_with_r, verify_proof};
use crate::error::Error;
use crate::group;
use crate::key::{PublicKey, SecretKey, derive_key_pair, generate_key_pair};
use crate::util::{HASH_TO_GROUP_DST, HASH_TO_SCALAR_DST, append_lp, check_lp_len, i2osp_2};

/// SHA-512 output length, used as the POPRF output length (`Nh`).
const HASH_LEN: usize = 64;

// ── wire types ────────────────────────────────────────────────────────────────

/// A blinded element sent from client to server (RFC 9497 §3.3.3).
///
/// Opaque on the wire: 32 bytes, canonical Ristretto compression. Identity
/// is rejected on parse (RFC 9497 §4.1).
#[derive(Clone)]
pub struct BlindedElement(pub(crate) RistrettoPoint);

/// An evaluated element returned from server to client (RFC 9497 §3.3.3).
///
/// Named `EvaluationElement` in RFC 9497; renamed here to avoid the
/// parsing ambiguity between "evaluation of an element" and "element used
/// for evaluation".
#[derive(Clone)]
pub struct EvaluatedElement(pub(crate) RistrettoPoint);

impl BlindedElement {
    /// Wire-format length: `Ne = 32` bytes.
    /// See: OPRF(ristretto255, SHA-512)
    pub const LEN: usize = group::ELEMENT_LEN;

    /// Serialize.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        group::serialize_element_array(&self.0)
    }

    /// Deserialize, rejecting the identity element and non-canonical encodings.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        Ok(Self(group::deserialize_element(buf)?))
    }
}

impl EvaluatedElement {
    /// Wire-format length: `Ne = 32` bytes.
    pub const LEN: usize = group::ELEMENT_LEN;

    /// Serialize.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        group::serialize_element_array(&self.0)
    }

    /// Deserialize, rejecting the identity element and non-canonical encodings.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        Ok(Self(group::deserialize_element(buf)?))
    }
}

impl fmt::Debug for BlindedElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_hex(f, "BlindedElement", &self.to_bytes())
    }
}

impl fmt::Debug for EvaluatedElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_hex(f, "EvaluatedElement", &self.to_bytes())
    }
}

// ── PoprfOutput ───────────────────────────────────────────────────────────────

/// POPRF output: SHA-512 digest (64 bytes).
///
/// Equality comparison is constant-time. The inner buffer is wiped on
/// drop via `ZeroizeOnDrop`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PoprfOutput(pub(crate) [u8; HASH_LEN]);

impl PoprfOutput {
    /// Output length: `Nh = 64` bytes for ristretto255-SHA512 (due to the hash).
    pub const LEN: usize = HASH_LEN;

    /// View the raw bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Construct from raw bytes (e.g. from a peer's serialized output).
    /// No validation other than length is possible.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() != Self::LEN {
            return Err(Error::Deserialize);
        }
        let mut arr = [0u8; Self::LEN];
        arr.copy_from_slice(buf);
        Ok(Self(arr))
    }
}

// uses subtle
impl ConstantTimeEq for PoprfOutput {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for PoprfOutput {
    // uses subtle
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for PoprfOutput {}

impl AsRef<[u8]> for PoprfOutput {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PoprfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PoprfOutput(<redacted>)")
    }
}

// ── client blind state ────────────────────────────────────────────────────────

/// Client-side state kept between [`PoprfClient::blind`] and
/// [`PoprfClient::finalize`].
///
/// # Security
///
/// Contains the **client-secret blinding scalar**. Never transmit a serialized
/// `PoprfBlindState` to the server: doing so reveals `blind` and breaks the
/// pseudorandomness of the protocol output. Wire serialization is provided
/// only for split-process or persisted-issuance flows where both endpoints
/// belong to the same client. `blind` is wiped on drop via `ZeroizeOnDrop`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PoprfBlindState {
    pub(crate) blind: Scalar,
    pub(crate) tweaked_key: RistrettoPoint,
}

impl PoprfBlindState {
    /// Wire-format length: `Ns + Ne = 64` bytes.
    pub const LEN: usize = group::SCALAR_LEN + group::ELEMENT_LEN;

    /// Serialize as `SerializeScalar(blind) || SerializeElement(tweakedKey)`.
    ///
    /// The serialized form contains the client-secret blinding scalar in
    /// the clear; treat it as confidential and zeroize the buffer when
    /// you're done with it.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..group::SCALAR_LEN].copy_from_slice(&group::serialize_scalar_array(&self.blind));
        out[group::SCALAR_LEN..]
            .copy_from_slice(&group::serialize_element_array(&self.tweaked_key));
        out
    }

    /// Parse from wire format. Rejects non-canonical scalars, identity
    /// `tweakedKey`, and non-canonical Ristretto encodings.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() != Self::LEN {
            return Err(Error::Deserialize);
        }
        let blind = group::deserialize_scalar(&buf[..group::SCALAR_LEN])?;
        let tweaked_key = group::deserialize_element(&buf[group::SCALAR_LEN..])?;
        Ok(Self { blind, tweaked_key })
    }
}

impl fmt::Debug for PoprfBlindState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `blind` is the client-secret scalar; never print it. `tweaked_key`
        // is a public group element (`m·G + pkS`) and may be printed.
        let tk = group::serialize_element_array(&self.tweaked_key);
        f.write_str("PoprfBlindState { blind: <redacted>, tweaked_key: ")?;
        for byte in &tk {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(" }")
    }
}

// ── client logic

/// POPRF client.
#[derive(Clone, Copy)]
pub struct PoprfClient {
    pk: RistrettoPoint,
}

impl PoprfClient {
    /// `SetupPOPRFClient(identifier, pkS)` — RFC 9497 §3.2.
    /// Takes as input the public key of the server.
    #[inline]
    #[must_use]
    pub fn new(pk: PublicKey) -> Self {
        Self { pk: pk.0 }
    }

    /// The server public key `pkS` this client was configured with.
    /// Takes as input the public key of the server.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.pk)
    }

    /// `Blind(input, info, pkS)` — RFC 9497 §3.3.3.
    /// Takes as input the `input` which is the element to be blinded,
    /// info, which is the public metadata.
    pub fn blind<R: RngCore + CryptoRng>(
        &self,
        input: &[u8],
        info: &[u8],
        rng: &mut R,
    ) -> Result<(PoprfBlindState, BlindedElement), Error> {
        let blind = group::random_scalar(rng);
        self.blind_with_inner(input, info, blind)
    }

    /// `Blind` with an externally-supplied 32-byte canonical blinding
    /// scalar. For RFC 9497 Appendix A test vectors and deterministic
    /// fixtures only — production code MUST use [`PoprfClient::blind`].
    /// A non-uniform or non-CSPRNG `blind` breaks the OPRF security
    /// argument.
    pub fn blind_with_scalar(
        &self,
        input: &[u8],
        info: &[u8],
        blind_bytes: &[u8; 32],
    ) -> Result<(PoprfBlindState, BlindedElement), Error> {
        let blind = group::deserialize_scalar(blind_bytes)?;
        self.blind_with_inner(input, info, blind)
    }

    // Auxiliary function for the public metadata
    fn blind_with_inner(
        &self,
        input: &[u8],
        info: &[u8],
        blind: Scalar,
    ) -> Result<(PoprfBlindState, BlindedElement), Error> {
        // RFC 9497 §5.1: `input` and `info` are length-prefixed with two
        // bytes throughout the protocol, so each MUST be smaller than
        // `2^16 - 1` bytes. Reject up-front to avoid silent `I2OSP(_, 2)`
        // truncation that would desynchronise the `Finalize` transcript.
        check_lp_len(input)?;
        check_lp_len(info)?;
        let framed = framed_info(info);
        let m = group::hash_to_scalar(&[&framed], HASH_TO_SCALAR_DST);
        let t = group::scalar_mul_gen(&m);
        let tweaked_key = group::element_add(&t, &self.pk);
        if bool::from(group::is_identity(&tweaked_key)) {
            return Err(Error::InvalidInput);
        }

        let input_element = group::hash_to_group(&[input], HASH_TO_GROUP_DST);
        if bool::from(group::is_identity(&input_element)) {
            return Err(Error::InvalidInput);
        }

        let blinded = group::scalar_mul(&blind, &input_element);
        Ok((
            PoprfBlindState { blind, tweaked_key },
            BlindedElement(blinded),
        ))
    }

    /// `Finalize(input, blind, evaluated, blinded, proof, info)` — RFC 9497 §3.3.3.
    ///
    /// Returns a [`PoprfOutput`]. Compare outputs with [`PoprfOutput`]'s
    /// `PartialEq` (constant-time) rather than reaching into raw bytes.
    pub fn finalize(
        &self,
        input: &[u8],
        state: &PoprfBlindState,
        evaluated: &EvaluatedElement,
        blinded: &BlindedElement,
        proof: &Proof,
        info: &[u8],
    ) -> Result<PoprfOutput, Error> {
        // RFC 9497 §5.1 length cap (see `blind_with_inner`).
        check_lp_len(input)?;
        check_lp_len(info)?;
        let g = group::generator();
        verify_proof(&g, &state.tweaked_key, &[evaluated.0], &[blinded.0], proof)?;
        Ok(self.unblind_and_hash(input, info, state, evaluated))
    }

    /// Batched `Finalize` for multiple inputs verified under one DLEQ proof.
    pub fn finalize_batch(
        &self,
        inputs: &[&[u8]],
        states: &[PoprfBlindState],
        evaluated: &[EvaluatedElement],
        blinded: &[BlindedElement],
        proof: &Proof,
        info: &[u8],
    ) -> Result<Vec<PoprfOutput>, Error> {
        if inputs.is_empty()
            || inputs.len() != states.len()
            || inputs.len() != evaluated.len()
            || inputs.len() != blinded.len()
        {
            return Err(Error::LengthMismatch);
        }
        // RFC 9497 §5.1 length cap on every input and the shared info.
        check_lp_len(info)?;
        for input in inputs {
            check_lp_len(input)?;
        }
        // A batched POPRF finalize covers a single (client, info) tuple, so
        // every state in the batch must carry the same `tweakedKey`. The
        // DLEQ proof is verified once against `states[0].tweaked_key`; if
        // any other state disagreed, the corresponding per-token
        // `unblind_and_hash` would still produce a value, but that value
        // would NOT match the server's `Evaluate(input_i, info)` output —
        // a silent desynchronisation. Reject up-front instead.
        let tweaked_key = states[0].tweaked_key;
        for s in &states[1..] {
            if !bool::from(s.tweaked_key.ct_eq(&tweaked_key)) {
                return Err(Error::InconsistentState);
            }
        }
        let g = group::generator();
        let bs: Vec<_> = blinded.iter().map(|b| b.0).collect();
        let es: Vec<_> = evaluated.iter().map(|e| e.0).collect();
        verify_proof(&g, &tweaked_key, &es, &bs, proof)?;

        let mut out = Vec::with_capacity(inputs.len());
        for ((input, state), e) in inputs.iter().zip(states.iter()).zip(evaluated.iter()) {
            out.push(self.unblind_and_hash(input, info, state, e));
        }
        Ok(out)
    }

    fn unblind_and_hash(
        &self,
        input: &[u8],
        info: &[u8],
        state: &PoprfBlindState,
        evaluated: &EvaluatedElement,
    ) -> PoprfOutput {
        let blind_inv = group::scalar_invert(&state.blind);
        let n = group::scalar_mul(&blind_inv, &evaluated.0);
        let n_bytes = group::serialize_element_array(&n);
        finalize_hash(input, info, &n_bytes)
    }
}

// ── server logic

/// POPRF server.
///
/// Wraps a long-term server [`SecretKey`] (wiped on drop via
/// `ZeroizeOnDrop`). Construction is zero-cost — the public key is derived
/// on demand from [`PoprfServer::public_key`], so building a `PoprfServer`
/// per request across an FFI boundary is cheap. Callers that need `pkS`
/// repeatedly should cache the returned value.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PoprfServer {
    sk: SecretKey,
}

impl PoprfServer {
    /// Construct from an existing secret key.
    #[inline]
    #[must_use]
    pub fn new(sk: SecretKey) -> Self {
        Self { sk }
    }

    /// Generate a fresh server with a random key.
    #[must_use = "discarding a freshly-generated server consumes RNG output \
                  for no reason"]
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let (sk, _) = generate_key_pair(rng);
        Self::new(sk)
    }

    /// Construct via `DeriveKeyPair(seed, info)` — RFC 9497 §3.2.1.
    ///
    /// The `seed` MUST be 32 bytes from a CSPRNG. `info` is included in
    /// the key-derivation hash and can be used to derive distinct keys
    /// from the same seed (e.g. one per deployment / per protocol
    /// version). Returns [`Error::DeriveKeyPair`] if the 256-iteration
    /// counter is exhausted (negligible probability).
    pub fn from_seed(seed: &[u8; 32], info: &[u8]) -> Result<Self, Error> {
        let (sk, _) = derive_key_pair(seed, info)?;
        Ok(Self::new(sk))
    }

    /// The server's public key `pkS = skS·G`. Performs one base-point
    /// scalar multiplication; cache the result if used repeatedly.
    #[inline]
    #[must_use = "deriving the server public key without using it performs \
                  a base-point scalar multiplication for nothing"]
    pub fn public_key(&self) -> PublicKey {
        self.sk.public_key()
    }

    /// The server's secret key `skS`. Treat as confidential.
    #[inline]
    #[must_use]
    pub fn secret_key(&self) -> &SecretKey {
        &self.sk
    }

    /// `BlindEvaluate(skS, blindedElement, info)` — RFC 9497 §3.3.3 (single token).
    /// Takes as an input the blinded element given by the client
    /// and the public metadata
    pub fn blind_evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded: &BlindedElement,
        info: &[u8],
    ) -> Result<(EvaluatedElement, Proof), Error> {
        // Defense-in-depth: BlindedElement::from_bytes already rejects
        // identity, but a caller that built one via the protocol path will
        // always pass through this code and we want to keep the invariant
        // even if construction paths evolve.
        if bool::from(group::is_identity(&blinded.0)) {
            return Err(Error::InputValidation);
        }
        let t = self.compute_t(info)?;
        let t_inv = group::scalar_invert(&t);
        let t_pub = group::scalar_mul_gen(&t);
        let evaluated = group::scalar_mul(&t_inv, &blinded.0);
        let g = group::generator();
        let proof = generate_proof(rng, &t, &g, &t_pub, &[evaluated], &[blinded.0]);
        Ok((EvaluatedElement(evaluated), proof))
    }

    /// `BlindEvaluate` with externally-supplied 32-byte proof randomness.
    /// For RFC 9497 Appendix A test vectors and deterministic fixtures
    /// only — production code MUST use [`PoprfServer::blind_evaluate`].
    /// A non-uniform or non-CSPRNG `proof_r_bytes` weakens the DLEQ
    /// proof's zero-knowledge property.
    pub fn blind_evaluate_with_proof_scalar(
        &self,
        blinded: &BlindedElement,
        info: &[u8],
        proof_r_bytes: &[u8; 32],
    ) -> Result<(EvaluatedElement, Proof), Error> {
        let proof_r = group::deserialize_scalar(proof_r_bytes)?;
        self.blind_evaluate_with_r_inner(blinded, info, &proof_r)
    }

    fn blind_evaluate_with_r_inner(
        &self,
        blinded: &BlindedElement,
        info: &[u8],
        proof_r: &Scalar,
    ) -> Result<(EvaluatedElement, Proof), Error> {
        if bool::from(group::is_identity(&blinded.0)) {
            return Err(Error::InputValidation);
        }
        let t = self.compute_t(info)?;
        let t_inv = group::scalar_invert(&t);
        let t_pub = group::scalar_mul_gen(&t);
        let evaluated = group::scalar_mul(&t_inv, &blinded.0);
        let g = group::generator();
        let proof = generate_proof_with_r(&t, &g, &t_pub, &[evaluated], &[blinded.0], proof_r);
        Ok((EvaluatedElement(evaluated), proof))
    }

    /// Batched `BlindEvaluate` — one DLEQ proof covers all tokens.
    pub fn blind_evaluate_batch<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded: &[BlindedElement],
        info: &[u8],
    ) -> Result<(Vec<EvaluatedElement>, Proof), Error> {
        if blinded.is_empty() {
            return Err(Error::LengthMismatch);
        }
        for b in blinded {
            if bool::from(group::is_identity(&b.0)) {
                return Err(Error::InputValidation);
            }
        }
        let t = self.compute_t(info)?;
        let t_inv = group::scalar_invert(&t);
        let t_pub = group::scalar_mul_gen(&t);

        let evals: Vec<_> = blinded
            .iter()
            .map(|b| group::scalar_mul(&t_inv, &b.0))
            .collect();
        let g = group::generator();
        let blinded_pts: Vec<_> = blinded.iter().map(|b| b.0).collect();
        let proof = generate_proof(rng, &t, &g, &t_pub, &evals, &blinded_pts);
        Ok((evals.into_iter().map(EvaluatedElement).collect(), proof))
    }

    /// Batched `BlindEvaluate` with externally-supplied 32-byte proof
    /// randomness. For RFC 9497 Appendix A test vectors only — production
    /// code MUST use [`PoprfServer::blind_evaluate_batch`].
    pub fn blind_evaluate_batch_with_proof_scalar(
        &self,
        blinded: &[BlindedElement],
        info: &[u8],
        proof_r_bytes: &[u8; 32],
    ) -> Result<(Vec<EvaluatedElement>, Proof), Error> {
        let proof_r = group::deserialize_scalar(proof_r_bytes)?;
        self.blind_evaluate_batch_with_r_inner(blinded, info, &proof_r)
    }

    fn blind_evaluate_batch_with_r_inner(
        &self,
        blinded: &[BlindedElement],
        info: &[u8],
        proof_r: &Scalar,
    ) -> Result<(Vec<EvaluatedElement>, Proof), Error> {
        if blinded.is_empty() {
            return Err(Error::LengthMismatch);
        }
        for b in blinded {
            if bool::from(group::is_identity(&b.0)) {
                return Err(Error::InputValidation);
            }
        }
        let t = self.compute_t(info)?;
        let t_inv = group::scalar_invert(&t);
        let t_pub = group::scalar_mul_gen(&t);

        let evals: Vec<_> = blinded
            .iter()
            .map(|b| group::scalar_mul(&t_inv, &b.0))
            .collect();
        let g = group::generator();
        let blinded_pts: Vec<_> = blinded.iter().map(|b| b.0).collect();
        let proof = generate_proof_with_r(&t, &g, &t_pub, &evals, &blinded_pts, proof_r);
        Ok((evals.into_iter().map(EvaluatedElement).collect(), proof))
    }

    /// `Evaluate(skS, input, info)` — offline POPRF (RFC 9497 §3.3.3).
    pub fn evaluate(&self, input: &[u8], info: &[u8]) -> Result<PoprfOutput, Error> {
        // RFC 9497 §5.1 length cap. `compute_t` enforces `info`.
        check_lp_len(input)?;
        let input_element = group::hash_to_group(&[input], HASH_TO_GROUP_DST);
        if bool::from(group::is_identity(&input_element)) {
            return Err(Error::InvalidInput);
        }
        let t = self.compute_t(info)?;
        let t_inv = group::scalar_invert(&t);
        let evaluated = group::scalar_mul(&t_inv, &input_element);
        let issued = group::serialize_element_array(&evaluated);
        Ok(finalize_hash(input, info, &issued))
    }

    /// Compute `t = skS + m` where `m = HashToScalar(framedInfo)`.
    ///
    /// Enforces the RFC 9497 §5.1 length cap on `info`; every server path
    /// that consumes `info` (`blind_evaluate*`, `evaluate`) routes through
    /// this function, so the check lives here once.
    fn compute_t(&self, info: &[u8]) -> Result<Scalar, Error> {
        check_lp_len(info)?;
        let framed = framed_info(info);
        let m = group::hash_to_scalar(&[&framed], HASH_TO_SCALAR_DST);
        let t = group::scalar_add(&self.sk.0, &m);
        if bool::from(group::scalar_is_zero(&t)) {
            return Err(Error::Inverse);
        }
        Ok(t)
    }
}

impl fmt::Debug for PoprfServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoprfServer")
            .field("public_key", &self.public_key())
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

// ── internal helpers ──────────────────────────────────────────────────────────

/// `framedInfo = "Info" || I2OSP(len(info), 2) || info`.
fn framed_info(info: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 2 + info.len());
    buf.extend_from_slice(b"Info");
    buf.extend_from_slice(&i2osp_2(info.len()));
    buf.extend_from_slice(info);
    buf
}

/// POPRF Finalize hash (RFC 9497 §3.3.3):
/// `Hash(I2OSP(len(input),2) || input || I2OSP(len(info),2) || info ||
///       I2OSP(len(unblinded),2) || unblinded || "Finalize")`.
fn finalize_hash(input: &[u8], info: &[u8], unblinded: &[u8]) -> PoprfOutput {
    let mut buf = Vec::with_capacity(
        2 + input.len() + 2 + info.len() + 2 + unblinded.len() + b"Finalize".len(),
    );
    append_lp(&mut buf, input);
    append_lp(&mut buf, info);
    append_lp(&mut buf, unblinded);
    buf.extend_from_slice(b"Finalize");

    let mut hasher = Sha512::default();
    Update::update(&mut hasher, &buf);
    let digest = FixedOutput::finalize_fixed(hasher);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest[..]);
    PoprfOutput(out)
}

fn debug_hex(f: &mut fmt::Formatter<'_>, name: &str, bytes: &[u8]) -> fmt::Result {
    f.write_str(name)?;
    f.write_str("(")?;
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    f.write_str(")")
}

// ── serde ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
mod serde_impls {
    use super::{BlindedElement, EvaluatedElement, PoprfBlindState, PoprfOutput};
    use crate::serde_util::{deser_fixed, ser_fixed};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for BlindedElement {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            ser_fixed(&self.to_bytes(), s)
        }
    }
    impl<'de> Deserialize<'de> for BlindedElement {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let bytes: [u8; Self::LEN] = deser_fixed::<{ Self::LEN }, _>(d)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }

    impl Serialize for EvaluatedElement {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            ser_fixed(&self.to_bytes(), s)
        }
    }
    impl<'de> Deserialize<'de> for EvaluatedElement {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let bytes: [u8; Self::LEN] = deser_fixed::<{ Self::LEN }, _>(d)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }

    impl Serialize for PoprfBlindState {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            ser_fixed(&self.to_bytes(), s)
        }
    }
    impl<'de> Deserialize<'de> for PoprfBlindState {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let bytes: [u8; Self::LEN] = deser_fixed::<{ Self::LEN }, _>(d)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }

    impl Serialize for PoprfOutput {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            ser_fixed(self.as_bytes(), s)
        }
    }
    impl<'de> Deserialize<'de> for PoprfOutput {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let bytes: [u8; Self::LEN] = deser_fixed::<{ Self::LEN }, _>(d)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}
