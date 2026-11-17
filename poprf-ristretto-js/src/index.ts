// Pure-JS client for RFC 9497 POPRF / ristretto255-SHA512: same API and wire
// format as @brave/poprf-ristretto-wasm, with the protocol done by @noble/curves.
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { concatBytes, equalBytes } from '@noble/curves/utils.js';

export type BlindBatchResult = { states: string[]; blindedMessages: string[] };

/** Blind each input; `states[i]` is base64 `blind || tweakedKey` (64 bytes), as in the wasm package. */
export function blindBatch(publicKeyB64: string, inputs: Uint8Array[], info: Uint8Array): BlindBatchResult {
  const pk = b64decode(publicKeyB64, 'public_key', 32);
  // wasm reads `.length`, so a non-array iterable would be an empty batch there.
  if (!Array.isArray(inputs)) throw new Error('blind: inputs must be an array');
  checkLength(info, 'blind');
  const poprf = ristretto255_oprf.poprf(info);
  // Up front so a bad key fails even for an empty batch (wasm skips the tweaked-key check there).
  deriveTweakedKey(poprf, pk);
  const states: string[] = [];
  const blindedMessages: string[] = [];
  // By index, like wasm and finalizeBatch: an overridden iterator would misalign the states.
  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i]!;
    checkLength(input, 'blind');
    const { blind, blinded, tweakedKey } = poprf.blind(input, pk);
    states.push(b64encode(concatBytes(blind, tweakedKey)));
    blindedMessages.push(b64encode(blinded));
  }
  return { states, blindedMessages };
}

/** Verify the batch DLEQ proof and unblind; returns one base64 64-byte output per input. */
export function finalizeBatch(
  publicKeyB64: string,
  inputs: Uint8Array[],
  states: string[],
  blindedMessages: string[],
  evaluatedElements: string[],
  proof: string,
  info: Uint8Array,
): string[] {
  // Like blindBatch: a Set has no .length, so it would read as an empty batch.
  if (![inputs, states, blindedMessages, evaluatedElements].every(Array.isArray)) {
    throw new Error('finalize_batch: arrays expected');
  }
  checkLength(info, 'finalize_batch');
  const poprf = ristretto255_oprf.poprf(info);
  const tweakedKey = deriveTweakedKey(poprf, b64decode(publicKeyB64, 'public_key', 32));
  const n = inputs.length;
  if (states.length !== n || blindedMessages.length !== n || evaluatedElements.length !== n) {
    throw new Error('finalize_batch: array length mismatch');
  }
  if (n === 0) throw new Error('finalize_batch: empty batch');
  // By index up to n, like wasm: an array's own iterator could yield other elements,
  // and holes come out undefined for noble's type check (map would skip them).
  const items = Array.from({ length: n }, (_, i) => {
    const input = inputs[i]!;
    checkLength(input, 'finalize_batch');
    const state = b64decode(states[i]!, 'state', 64);
    // Every state must come from this pk and info (as in the Rust core): a clear error
    // instead of a failed proof against the tweaked key derived above.
    if (!equalBytes(state.subarray(32), tweakedKey)) {
      throw new Error('finalize_batch: state does not match the public key and info');
    }
    return {
      input,
      blind: state.subarray(0, 32),
      blinded: b64decode(blindedMessages[i]!, 'blinded', 32),
      evaluated: b64decode(evaluatedElements[i]!, 'evaluated', 32),
    };
  });
  const proofBytes = b64decode(proof, 'proof', 64);
  return poprf.finalizeBatch(items, proofBytes, tweakedKey).map(b64encode);
}

// noble's blind checks pk (rejecting the identity, RFC 9497 §3.3) and computes
// G * HashToScalar(info) + pk; the empty-input blind itself is discarded.
// Structural `poprf` type: tsc rejects ReturnType<typeof ristretto255_oprf.poprf> here.
function deriveTweakedKey(
  poprf: { blind(input: Uint8Array, pk: Uint8Array): { tweakedKey: Uint8Array } },
  pk: Uint8Array,
): Uint8Array {
  try {
    return poprf.blind(new Uint8Array(), pk).tweakedKey;
  } catch (e) {
    throw new Error(`PublicKey: ${(e as Error).message}`);
  }
}

// RFC 9497 §5.1: input and info must be shorter than 2^16 - 1 bytes; noble admits 2^16 - 1.
function checkLength(bytes: Uint8Array, what: string): void {
  // `?.`: non-bytes fall through to noble's own type check.
  if (bytes?.length >= 0xffff) throw new Error(`${what}: input or info length must be smaller than 2^16 - 1 bytes`);
}

function b64encode(bytes: Uint8Array): string {
  // No spread: a huge argument list overflows the stack.
  return btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(''));
}

// Canonical padded base64 only, like the Rust `base64` STANDARD engine behind
// the wasm package. The round trip below enforces it (atob alone tolerates
// whitespace and missing padding); the regex gives atob's rejects our error prefix.
function b64decode(s: string, what: string, len: number): Uint8Array {
  if (typeof s !== 'string') throw new Error(`${what} must be string`);
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new Error(`${what} base64: invalid encoding`);
  }
  const bytes = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  // Non-zero trailing bits decode like zero ones; re-encoding rejects them.
  if (b64encode(bytes) !== s) throw new Error(`${what} base64: non-canonical encoding`);
  if (bytes.length !== len) throw new Error(`${what}: expected ${len} bytes, got ${bytes.length}`);
  return bytes;
}
