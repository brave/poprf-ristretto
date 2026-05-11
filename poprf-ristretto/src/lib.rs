//! # poprf-ristretto
//!
//! RFC 9497 **Partially-Oblivious Pseudorandom Function** (POPRF) over the
//! `ristretto255-SHA512` ciphersuite.
//!
//! Implements the POPRF protocol variant from
//! [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497) §3.3.3 with the
//! ristretto255-SHA512 ciphersuite defined in §4.1. All RFC 9497 Appendix A
//! test vectors for POPRF/ristretto255-SHA512 pass.
//!
//! ## Quick start
//!
//! ```rust
//! # #[cfg(feature = "std")] {
//! use poprf_ristretto::{PoprfClient, PoprfServer};
//! use rand_core::OsRng;
//!
//! let server = PoprfServer::generate(&mut OsRng);
//! let client = PoprfClient::new(server.public_key());
//!
//! let input = b"my secret input";
//! let info  = b"public context";
//!
//! let (state, blinded) = client.blind(input, info, &mut OsRng).unwrap();
//! let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();
//! let output = client
//!     .finalize(input, &state, &evaluated, &blinded, &proof, info)
//!     .expect("proof verified");
//!
//! // Server-side offline evaluation must agree.
//! assert_eq!(output, server.evaluate(input, info).unwrap());
//! # }
//! ```
//!
//! ## Wire format
//!
//! Every wire-bound type exposes a fixed-size byte serialization
//! (`from_bytes` / `to_bytes` / `LEN` constant). All `from_bytes`
//! implementations enforce canonical encoding (RFC 9496 §A.2) and reject
//! the identity element on `Element` types (RFC 9497 §4.1).
//!
//! | Type                 | `LEN`       | Source           |
//! |----------------------|-------------|------------------|
//! | [`SecretKey`]        | 32 (`Ns`)   | server           |
//! | [`PublicKey`]        | 32 (`Ne`)   | server → client  |
//! | [`BlindedElement`]   | 32 (`Ne`)   | client → server  |
//! | [`EvaluatedElement`] | 32 (`Ne`)   | server → client  |
//! | [`Proof`]            | 64 (`2·Ns`) | server → client  |
//! | [`PoprfBlindState`]  | 64 (`Ns + Ne`) | client-internal  |
//! | [`PoprfOutput`]      | 64 (`Nh`)   | client / server  |
//!
//! ## Security
//!
//! * **Constant-time discipline.** [`PoprfClient::finalize`],
//!   [`PoprfClient::finalize_batch`], [`PoprfServer::blind_evaluate`],
//!   [`PoprfServer::blind_evaluate_batch`], and [`PoprfServer::evaluate`]
//!   are constant-time in every secret scalar: `skS`, the client `blind`,
//!   the DLEQ proof nonce `r`, and the per-`info` evaluation scalar
//!   `t = skS + m`. The test-vector siblings
//!   ([`PoprfClient::blind_with_scalar`],
//!   [`PoprfServer::blind_evaluate_with_proof_scalar`],
//!   [`PoprfServer::blind_evaluate_batch_with_proof_scalar`]) share the
//!   same path; the caller supplies the random scalar instead of sampling
//!   it from a CSPRNG. DLEQ challenge equality uses
//!   `subtle::ConstantTimeEq`. [`PoprfOutput`] equality is constant-time.
//! * **`fast-dleq` vartime MSM** is used for DLEQ composite computation.
//!   This is safe because the per-element scalars `dᵢ` are derived from a
//!   public Fiat-Shamir transcript (RFC 9497 §2.2.1) and contain no
//!   secret input.
//! * **Secret material.** [`SecretKey`] is server-secret. [`PoprfBlindState`]
//!   contains the client-secret blinding scalar; never transmit it to the
//!   server. All secret-bearing types ([`SecretKey`], [`PoprfServer`],
//!   [`PoprfBlindState`], [`PoprfOutput`]) implement `ZeroizeOnDrop` and
//!   are wiped automatically when they go out of scope. [`Proof`] is wire
//!   data with no secret content (see its type-level docs) and is not
//!   zeroized.
//! * **`info` parameter.** Both client and server must agree on `info`
//!   out-of-band. A mismatch yields [`Error::Verify`] on the client (the
//!   reconstructed `tweakedKey` will not match the server's), not silent
//!   garbage.
//! * **Domain separation.** Every hash invocation is namespaced with a DST
//!   of the form `<label> || "OPRFV1-" || I2OSP(mode, 1) || "-" || suite_id`
//!   per RFC 9497 §3.1 / §4.
//!
//! ## Cargo features
//!
//! | Feature              | Default | Description |
//! |----------------------|---------|-------------|
//! | `std`                | yes     | Enables `std::error::Error` impl on [`Error`]. |
//! | `alloc`              | yes     | Required by all protocol APIs (implied by `std`). |
//! | `fast-dleq`          | yes     | Vartime Pippenger MSM in DLEQ composite computation. |
//! | `precomputed-tables` | yes     | Precomputed multiples of the base point (+~30 KB rodata). |
//! | `serde`              | no      | `serde::{Serialize, Deserialize}` for wire types. |
//!
//! At least one of `std` or `alloc` is required to build — the batched
//! protocol APIs return `Vec`. The crate is `#![no_std]`-capable with
//! `alloc`. `ZeroizeOnDrop` on secret-bearing types is unconditional;
//! there is no cargo feature to disable it.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::type_complexity)]

#[cfg(not(feature = "alloc"))]
compile_error!(
    "poprf-ristretto requires the `alloc` feature (enabled by default via `std`). \
     The batched protocol APIs return `Vec`. Enable `alloc` or `std`."
);

extern crate alloc;

mod dleq;
mod error;
mod group;
mod key;
mod poprf;
#[cfg(feature = "serde")]
mod serde_util;
mod util;

pub use dleq::Proof;
pub use error::Error;
pub use key::{PublicKey, SecretKey, derive_key_pair, generate_key_pair};
pub use poprf::{
    BlindedElement, EvaluatedElement, PoprfBlindState, PoprfClient, PoprfOutput, PoprfServer,
};

/// Mode identifier for POPRF (RFC 9497 §3.1).
pub const MODE_POPRF: u8 = 0x02;

/// RFC 9497 ciphersuite identifier for this crate.
pub const SUITE_ID: &str = "ristretto255-SHA512";
