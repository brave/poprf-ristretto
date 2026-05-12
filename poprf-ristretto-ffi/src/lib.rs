//! C ABI for `poprf-ristretto`.
//!
//! Opaque-pointer wrappers for the POPRF/ristretto255-SHA512 protocol
//! defined in RFC 9497. The header (`include/poprf_ristretto_ffi.h`) is
//! generated from this file via `cbindgen` and checked in.
//!
//! See the crate-level README for the object model, ownership rules,
//! and a worked C example. Each `pub unsafe extern "C" fn` below
//! carries its own `# Safety` block.

use core::cell::RefCell;
use core::ffi::{c_char, c_int};
use core::ptr;
use std::ffi::CString;
use std::slice;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand_core::OsRng;

use poprf_ristretto::{
    BlindedElement, EvaluatedElement, PoprfOutput, PoprfServer, Proof, PublicKey, SecretKey,
};

// ── thread-local last error ──────────────────────────────────────────────────

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_error(msg: &str) {
    let cstr = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
    LAST_ERROR.with(|cell| *cell.borrow_mut() = Some(cstr));
}

fn clear_error() {
    LAST_ERROR.with(|cell| *cell.borrow_mut() = None);
}

/// Return the last error message for this thread, or NULL if none.
///
/// The returned pointer is owned by the caller and must be freed with
/// [`poprf_c_char_destroy`].
#[unsafe(no_mangle)]
pub extern "C" fn poprf_last_error_message() -> *mut c_char {
    LAST_ERROR.with(|cell| match cell.borrow().as_ref() {
        Some(s) => match CString::new(s.as_bytes()) {
            Ok(c) => c.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    })
}

/// Free a string returned by any `*_b64` or [`poprf_last_error_message`] call.
///
/// # Safety
///
/// `s` must be either NULL or a pointer previously returned by this library
/// and never yet freed. Double-free is undefined behaviour. Passing a
/// pointer obtained from a different allocator is undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_c_char_destroy(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        drop(CString::from_raw(s));
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Wrap `(ptr, len)` as `&[u8]`. Tolerates `(NULL, 0)` (returns empty slice).
///
/// # Safety
///
/// If `ptr` is non-null, the caller must guarantee that `ptr..ptr+len` is a
/// valid readable region for the lifetime of the returned slice and that no
/// other thread mutates it during that time.
unsafe fn bytes_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    unsafe {
        if ptr.is_null() {
            if len == 0 { Some(&[]) } else { None }
        } else {
            Some(slice::from_raw_parts(ptr, len))
        }
    }
}

fn cstring_or_null(buf: &[u8]) -> *mut c_char {
    let s = B64.encode(buf);
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            set_error("internal: NUL in base64 output");
            ptr::null_mut()
        }
    }
}

// ── SecretKey ────────────────────────────────────────────────────────────────

/// Derive a [`SecretKey`] from a 32-byte CSPRNG seed (RFC 9497 §3.2.1).
///
/// `seed_len` MUST be exactly 32. Callers holding a longer KDF output
/// MUST extract a 32-byte slice of full entropy on their side and pass
/// it here. Returning NULL on `seed_len != 32` prevents accidental
/// silent truncation that would hide upstream contract drift.
///
/// `info` is the application-bound key-derivation context (RFC 9497
/// §3.2.1, length-prefixed inside `DeriveKeyPair`). It MUST be smaller
/// than `2^16 - 1` bytes per RFC 9497 §5.1.
///
/// On success, returns an owned `*mut SecretKey` that must be freed via
/// [`poprf_secret_key_destroy`]. Returns NULL on error.
///
/// # Safety
///
/// - `seed_ptr` must be either NULL with `seed_len == 0`, or point to
///   `seed_len` initialised bytes.
/// - `info_ptr` must be either NULL with `info_len == 0`, or point to
///   `info_len` initialised bytes.
/// - The library reads from both buffers but does not retain them after
///   the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_secret_key_from_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    info_ptr: *const u8,
    info_len: usize,
) -> *mut SecretKey {
    unsafe {
        clear_error();
        let seed = match bytes_from_raw(seed_ptr, seed_len) {
            Some(s) if s.len() == 32 => s,
            _ => {
                set_error("seed must be exactly 32 bytes");
                return ptr::null_mut();
            }
        };
        let info = match bytes_from_raw(info_ptr, info_len) {
            Some(i) => i,
            None => {
                set_error("invalid info pointer");
                return ptr::null_mut();
            }
        };
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed);
        match poprf_ristretto::derive_key_pair(&seed_arr, info) {
            Ok((sk, _pk)) => Box::into_raw(Box::new(sk)),
            Err(e) => {
                set_error(&format!("derive_key_pair: {e}"));
                ptr::null_mut()
            }
        }
    }
}

/// Decode a [`SecretKey`] from its 32-byte canonical encoding (base64).
///
/// On success, returns an owned `*mut SecretKey` that must be freed via
/// [`poprf_secret_key_destroy`]. Returns NULL on error.
///
/// # Safety
///
/// `s_ptr` must be either NULL with `s_len == 0`, or point to `s_len`
/// initialised bytes (the base64-encoded form, without trailing NUL).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_secret_key_decode_base64(
    s_ptr: *const u8,
    s_len: usize,
) -> *mut SecretKey {
    unsafe {
        clear_error();
        let s = match bytes_from_raw(s_ptr, s_len) {
            Some(s) => s,
            None => {
                set_error("invalid base64 pointer");
                return ptr::null_mut();
            }
        };
        let bytes = match B64.decode(s) {
            Ok(b) => b,
            Err(e) => {
                set_error(&format!("base64 decode: {e}"));
                return ptr::null_mut();
            }
        };
        match SecretKey::from_bytes(&bytes) {
            Ok(sk) => Box::into_raw(Box::new(sk)),
            Err(e) => {
                set_error(&format!("SecretKey::from_bytes: {e}"));
                ptr::null_mut()
            }
        }
    }
}

/// Encode a [`SecretKey`] as base64 of its 32-byte canonical form.
///
/// Returns a NUL-terminated heap string the caller must free with
/// [`poprf_c_char_destroy`], or NULL on error.
///
/// # Safety
///
/// `sk` must be either NULL or a valid pointer returned by a constructor
/// in this library and not yet destroyed. The pointee is not modified.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_secret_key_encode_base64(sk: *const SecretKey) -> *mut c_char {
    unsafe {
        clear_error();
        if sk.is_null() {
            set_error("null SecretKey");
            return ptr::null_mut();
        }
        cstring_or_null(&(*sk).to_bytes())
    }
}

/// Free a [`SecretKey`] returned by a constructor in this library.
///
/// # Safety
///
/// `sk` must be either NULL or a pointer previously returned by this
/// library and not yet destroyed. Double-free is undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_secret_key_destroy(sk: *mut SecretKey) {
    unsafe {
        if !sk.is_null() {
            drop(Box::from_raw(sk));
        }
    }
}

// ── PublicKey ────────────────────────────────────────────────────────────────

/// Derive the [`PublicKey`] corresponding to `sk`.
///
/// On success, returns an owned `*mut PublicKey` that must be freed via
/// [`poprf_public_key_destroy`]. Returns NULL on error.
///
/// # Safety
///
/// `sk` must be either NULL or a valid pointer returned by a constructor
/// in this library and not yet destroyed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_public_key_from_secret(sk: *const SecretKey) -> *mut PublicKey {
    unsafe {
        clear_error();
        if sk.is_null() {
            set_error("null SecretKey");
            return ptr::null_mut();
        }
        Box::into_raw(Box::new((*sk).public_key()))
    }
}

/// Encode a [`PublicKey`] as base64 of its 32-byte canonical form.
///
/// Returns a NUL-terminated heap string the caller must free with
/// [`poprf_c_char_destroy`], or NULL on error.
///
/// # Safety
///
/// `pk` must be either NULL or a valid pointer returned by a constructor
/// in this library and not yet destroyed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_public_key_encode_base64(pk: *const PublicKey) -> *mut c_char {
    unsafe {
        clear_error();
        if pk.is_null() {
            set_error("null PublicKey");
            return ptr::null_mut();
        }
        cstring_or_null(&(*pk).to_bytes())
    }
}

/// Free a [`PublicKey`] returned by a constructor in this library.
///
/// # Safety
///
/// `pk` must be either NULL or a pointer previously returned by this
/// library and not yet destroyed. Double-free is undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_public_key_destroy(pk: *mut PublicKey) {
    unsafe {
        if !pk.is_null() {
            drop(Box::from_raw(pk));
        }
    }
}

// ── BlindedElement ───────────────────────────────────────────────────────────

/// Decode a [`BlindedElement`] from its 32-byte canonical ristretto255
/// encoding (base64).
///
/// On success, returns an owned `*mut BlindedElement` that must be freed via
/// [`poprf_blinded_element_destroy`]. Returns NULL on error.
///
/// # Safety
///
/// `s_ptr` must be either NULL with `s_len == 0`, or point to `s_len`
/// initialised bytes (the base64-encoded form, without trailing NUL).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_blinded_element_decode_base64(
    s_ptr: *const u8,
    s_len: usize,
) -> *mut BlindedElement {
    unsafe {
        clear_error();
        let s = match bytes_from_raw(s_ptr, s_len) {
            Some(s) => s,
            None => {
                set_error("invalid base64 pointer");
                return ptr::null_mut();
            }
        };
        let bytes = match B64.decode(s) {
            Ok(b) => b,
            Err(e) => {
                set_error(&format!("base64 decode: {e}"));
                return ptr::null_mut();
            }
        };
        match BlindedElement::from_bytes(&bytes) {
            Ok(b) => Box::into_raw(Box::new(b)),
            Err(e) => {
                set_error(&format!("BlindedElement::from_bytes: {e}"));
                ptr::null_mut()
            }
        }
    }
}

/// Free a [`BlindedElement`] returned by a constructor in this library.
///
/// # Safety
///
/// `b` must be either NULL or a pointer previously returned by this
/// library and not yet destroyed. Double-free is undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_blinded_element_destroy(b: *mut BlindedElement) {
    unsafe {
        if !b.is_null() {
            drop(Box::from_raw(b));
        }
    }
}

// ── EvaluatedElement ─────────────────────────────────────────────────────────

/// Encode an [`EvaluatedElement`] as base64 of its 32-byte canonical
/// ristretto255 encoding.
///
/// Returns a NUL-terminated heap string the caller must free with
/// [`poprf_c_char_destroy`], or NULL on error.
///
/// # Safety
///
/// `e` must be either NULL or a valid pointer returned by a constructor
/// in this library and not yet destroyed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_evaluated_element_encode_base64(
    e: *const EvaluatedElement,
) -> *mut c_char {
    unsafe {
        clear_error();
        if e.is_null() {
            set_error("null EvaluatedElement");
            return ptr::null_mut();
        }
        cstring_or_null(&(*e).to_bytes())
    }
}

/// Free an [`EvaluatedElement`] returned by a constructor in this library.
///
/// # Safety
///
/// `e` must be either NULL or a pointer previously returned by this
/// library and not yet destroyed. Double-free is undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_evaluated_element_destroy(e: *mut EvaluatedElement) {
    unsafe {
        if !e.is_null() {
            drop(Box::from_raw(e));
        }
    }
}

// ── Proof ────────────────────────────────────────────────────────────────────

/// Encode a DLEQ [`Proof`] as base64 of its 64-byte canonical form
/// (two scalars).
///
/// Returns a NUL-terminated heap string the caller must free with
/// [`poprf_c_char_destroy`], or NULL on error.
///
/// # Safety
///
/// `p` must be either NULL or a valid pointer returned by a constructor
/// in this library and not yet destroyed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_proof_encode_base64(p: *const Proof) -> *mut c_char {
    unsafe {
        clear_error();
        if p.is_null() {
            set_error("null Proof");
            return ptr::null_mut();
        }
        cstring_or_null(&(*p).to_bytes())
    }
}

/// Free a [`Proof`] returned by a constructor in this library.
///
/// # Safety
///
/// `p` must be either NULL or a pointer previously returned by this
/// library and not yet destroyed. Double-free is undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_proof_destroy(p: *mut Proof) {
    unsafe {
        if !p.is_null() {
            drop(Box::from_raw(p));
        }
    }
}

// ── BlindEvaluate (batched) ──────────────────────────────────────────────────

/// Server-side batched blind-evaluate (RFC 9497 §3.3.3).
///
/// Inputs:
/// - `sk`: server secret key.
/// - `blinded_arr` / `n`: array of `n` non-NULL [`BlindedElement`] pointers.
/// - `info_ptr` / `info_len`: POPRF `info` parameter.
/// - `out_evaluated`: out-array of length `n`. Receives owned
///   [`EvaluatedElement`] pointers on success. The caller is responsible for
///   destroying each via [`poprf_evaluated_element_destroy`].
/// - `out_proof`: receives an owned [`Proof`] pointer on success.
///
/// Returns 0 on success, non-zero on failure. On failure no output pointers
/// are written (caller's `out_*` slots are left untouched).
///
/// # Safety
///
/// - `sk` must be a valid non-NULL pointer to a `SecretKey` returned by
///   this library.
/// - `blinded_arr` must be a valid non-NULL pointer to `n` consecutive
///   `*const BlindedElement` pointers, each of which is a valid pointer
///   returned by this library and not yet destroyed.
/// - `info_ptr` must be either NULL with `info_len == 0`, or point to
///   `info_len` initialised bytes.
/// - `out_evaluated` must be a valid non-NULL pointer to `n` writable
///   `*mut EvaluatedElement` slots, suitably aligned.
/// - `out_proof` must be a valid non-NULL pointer to one writable
///   `*mut Proof` slot, suitably aligned.
/// - `n` must accurately describe the lengths of `blinded_arr` and
///   `out_evaluated`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_blind_evaluate_batch(
    sk: *const SecretKey,
    blinded_arr: *const *const BlindedElement,
    n: usize,
    info_ptr: *const u8,
    info_len: usize,
    out_evaluated: *mut *mut EvaluatedElement,
    out_proof: *mut *mut Proof,
) -> c_int {
    unsafe {
        clear_error();
        if sk.is_null() || blinded_arr.is_null() || out_evaluated.is_null() || out_proof.is_null() {
            set_error("null pointer in blind_evaluate_batch");
            return -1;
        }
        if n == 0 {
            set_error("blind_evaluate_batch requires n >= 1");
            return -1;
        }
        let info = match bytes_from_raw(info_ptr, info_len) {
            Some(i) => i,
            None => {
                set_error("invalid info pointer");
                return -1;
            }
        };

        // Collect input slice. Each pointer must be non-null.
        let ptrs = slice::from_raw_parts(blinded_arr, n);
        let mut blindeds: Vec<BlindedElement> = Vec::with_capacity(n);
        for (i, p) in ptrs.iter().enumerate() {
            if p.is_null() {
                set_error(&format!("null BlindedElement at index {i}"));
                return -1;
            }
            blindeds.push((*(*p)).clone());
        }

        let server = PoprfServer::new((*sk).clone());
        let (evaluateds, proof) = match server.blind_evaluate_batch(&mut OsRng, &blindeds, info) {
            Ok(t) => t,
            Err(e) => {
                set_error(&format!("blind_evaluate_batch: {e}"));
                return -1;
            }
        };

        if evaluateds.len() != n {
            set_error("evaluated count mismatch");
            return -1;
        }

        let out_eval_slice = slice::from_raw_parts_mut(out_evaluated, n);
        for (i, e) in evaluateds.into_iter().enumerate() {
            out_eval_slice[i] = Box::into_raw(Box::new(e));
        }
        *out_proof = Box::into_raw(Box::new(proof));
        0
    }
}

// ── Server-side Evaluate ─────────────────────────────────────────────────────

/// Server-side offline evaluation (RFC 9497 §3.3.3 `Evaluate`).
///
/// Returns the 64-byte POPRF output for `(input, info)` under `sk`, or NULL
/// on error. The returned [`PoprfOutput`] must be freed via
/// [`poprf_output_destroy`].
///
/// `input` and `info` MUST each be smaller than `2^16 - 1` bytes
/// per RFC 9497 §5.1; otherwise this returns NULL.
///
/// # Safety
///
/// - `sk` must be either NULL or a valid pointer returned by a constructor
///   in this library and not yet destroyed.
/// - `input_ptr` must be either NULL with `input_len == 0`, or point to
///   `input_len` initialised bytes.
/// - `info_ptr` must be either NULL with `info_len == 0`, or point to
///   `info_len` initialised bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_evaluate(
    sk: *const SecretKey,
    input_ptr: *const u8,
    input_len: usize,
    info_ptr: *const u8,
    info_len: usize,
) -> *mut PoprfOutput {
    unsafe {
        clear_error();
        if sk.is_null() {
            set_error("null SecretKey");
            return ptr::null_mut();
        }
        let input = match bytes_from_raw(input_ptr, input_len) {
            Some(i) => i,
            None => {
                set_error("invalid input pointer");
                return ptr::null_mut();
            }
        };
        let info = match bytes_from_raw(info_ptr, info_len) {
            Some(i) => i,
            None => {
                set_error("invalid info pointer");
                return ptr::null_mut();
            }
        };
        let server = PoprfServer::new((*sk).clone());
        match server.evaluate(input, info) {
            Ok(out) => Box::into_raw(Box::new(out)),
            Err(e) => {
                set_error(&format!("evaluate: {e}"));
                ptr::null_mut()
            }
        }
    }
}

/// Encode a [`PoprfOutput`] as base64 of its 64-byte value.
///
/// Returns a NUL-terminated heap string the caller must free with
/// [`poprf_c_char_destroy`], or NULL on error.
///
/// # Safety
///
/// `o` must be either NULL or a valid pointer returned by a constructor
/// in this library and not yet destroyed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_output_encode_base64(o: *const PoprfOutput) -> *mut c_char {
    unsafe {
        clear_error();
        if o.is_null() {
            set_error("null PoprfOutput");
            return ptr::null_mut();
        }
        cstring_or_null((*o).as_bytes())
    }
}

/// Constant-time equality of a [`PoprfOutput`] against a base64-encoded
/// expected 64-byte value.
///
/// Returns 1 if equal, 0 if different, -1 on error (invalid base64 etc).
///
/// # Safety
///
/// - `o` must be either NULL or a valid pointer returned by a constructor
///   in this library and not yet destroyed.
/// - `expected_b64_ptr` must be either NULL with `expected_b64_len == 0`,
///   or point to `expected_b64_len` initialised bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_output_eq_base64(
    o: *const PoprfOutput,
    expected_b64_ptr: *const u8,
    expected_b64_len: usize,
) -> c_int {
    unsafe {
        clear_error();
        if o.is_null() {
            set_error("null PoprfOutput");
            return -1;
        }
        let s = match bytes_from_raw(expected_b64_ptr, expected_b64_len) {
            Some(s) => s,
            None => {
                set_error("invalid expected b64 pointer");
                return -1;
            }
        };
        let bytes = match B64.decode(s) {
            Ok(b) => b,
            Err(e) => {
                set_error(&format!("base64 decode: {e}"));
                return -1;
            }
        };
        let other = match PoprfOutput::from_bytes(&bytes) {
            Ok(o) => o,
            Err(e) => {
                set_error(&format!("PoprfOutput::from_bytes: {e}"));
                return -1;
            }
        };
        if (*o) == other { 1 } else { 0 }
    }
}

/// Free a [`PoprfOutput`] returned by a constructor in this library.
///
/// # Safety
///
/// `o` must be either NULL or a pointer previously returned by this
/// library and not yet destroyed. Double-free is undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poprf_output_destroy(o: *mut PoprfOutput) {
    unsafe {
        if !o.is_null() {
            drop(Box::from_raw(o));
        }
    }
}
