// Negative paths: the JS client must reject everything the Rust client and its
// wasm binding reject. Each test cites the poprf-ristretto/tests/negative.rs case it ports.
import assert from 'node:assert/strict';
import test from 'node:test';
import { ristretto255, ristretto255_oprf } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, concatBytes, numberToBytesLE } from '@noble/curves/utils.js';
import { blindBatch, finalizeBatch } from '../src/index.ts';
import { b64, fromB64, hex } from './util.ts';

const enc = new TextEncoder();
const info = enc.encode('test-info');

// noble plays the server so every case starts from an honest, verifying batch.
const server = ristretto255_oprf.poprf(info).generateKeyPair();
const pk = b64(server.publicKey);

function honest(inputs: Uint8Array[] = [enc.encode('input')], i: Uint8Array = info) {
  const { states, blindedMessages } = blindBatch(pk, inputs, i);
  const res = ristretto255_oprf.poprf(i).blindEvaluateBatch(server.secretKey, blindedMessages.map(fromB64));
  return { pk, inputs, states, blinded: blindedMessages, evaluated: res.evaluated.map(b64), proof: b64(res.proof), info: i };
}

const finalize = (b: ReturnType<typeof honest>) => finalizeBatch(b.pk, b.inputs, b.states, b.blinded, b.evaluated, b.proof, b.info);

// Swap tweakedKey (state bytes 32..64) for `key`.
const withTweakedKey = (state: string, key: Uint8Array) => b64(concatBytes(fromB64(state).subarray(0, 32), key));

// Bad 32-byte element encodings, copied from negative.rs.
const identity = new Uint8Array(32);
const nonCanonical = [
  [0x00, ...Array(31).fill(0xff)],
  [...Array(31).fill(0xff), 0x7f],
  [0xf3, ...Array(30).fill(0xff), 0x7f],
  [0xed, ...Array(30).fill(0xff), 0x7f],
].map((a) => new Uint8Array(a));
const negative = new Uint8Array(32);
negative[0] = 0x01; // s = 1, IS_NEGATIVE
// s = 1 also fails decode step 2, so add a negated real encoding (p - s), which fails only step 1.
const negated = numberToBytesLE(2n ** 255n - 19n - bytesToNumberLE(server.publicKey), 32);
// RFC 9496 A.2: canonical non-negative encodings that fail decode step 2 (non-square x^2, negative x*y, s = -1).
const failStep2 = [
  '26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371',
  '4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f',
  'de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b',
  'bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042',
  '2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08',
  'f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22',
  '8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731',
  '2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b',
  '3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e',
  'a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220',
  'd483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e',
  '8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32',
  '32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b',
  '227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165',
  '5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e',
  '445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
].map(hex);

// noble's decoder errors: any byte change also breaks the DLEQ, so a bare
// assert.throws would pass on "proof verification failed" even if decoding regressed.
const decodeError = /point at infinity|invalid ristretto255 encoding|outside of range/;

const mismatch = /^Error: finalize_batch: state does not match the public key and info/;

// Every place a 32-byte wire element enters the client.
function assertElementRejected(bad: Uint8Array) {
  const b = honest();
  assert.throws(() => blindBatch(b64(bad), [], info), /^Error: PublicKey: /);
  assert.throws(() => finalize({ ...b, pk: b64(bad) }), /^Error: PublicKey: /);
  assert.throws(() => finalize({ ...b, blinded: [b64(bad)] }), decodeError);
  assert.throws(() => finalize({ ...b, evaluated: [b64(bad)] }), decodeError);
  // Compared against the key derived from (pk, info), so it never reaches the decoder.
  assert.throws(() => finalize({ ...b, states: [withTweakedKey(b.states[0]!, bad)] }), mismatch);
}

test('honest batch finalizes (control for every case below)', () => {
  const b = honest([enc.encode('a'), enc.encode('b'), enc.encode('c')]);
  const out = finalize(b);
  const direct = b.inputs.map((x) => b64(ristretto255_oprf.poprf(info).evaluate(server.secretKey, x)));
  assert.deepEqual(out, direct);
});

// from_bytes_rejects_identity
test('rejects the identity element', () => assertElementRejected(identity));

// from_bytes_rejects_non_canonical_field_element
test('rejects non-canonical field element encodings', () => {
  for (const bad of nonCanonical) assertElementRejected(bad);
});

// from_bytes_rejects_negative_field_element
test('rejects negative field element encodings', () => {
  assertElementRejected(negative);
  assertElementRejected(negated);
});

// JS-only: RFC 9496 A.2 encodings that only decode step 2 rejects.
test('rejects encodings failing ristretto decode step 2', () => {
  for (const bad of failStep2) assertElementRejected(bad);
});

// JS-only: a key with tweakedKey = G * HashToScalar(info) + pk = identity (RFC 9497 §3.3.3).
test('rejects a public key whose tweaked key is the identity', () => {
  const p = ristretto255.Point.fromBytes(server.publicKey);
  const t = ristretto255.Point.fromBytes(ristretto255_oprf.poprf(info).blind(new Uint8Array(), server.publicKey).tweakedKey);
  const bad = b64(p.subtract(t).toBytes());
  assert.throws(() => blindBatch(bad, [], info), /^Error: PublicKey: /);
  assert.throws(() => blindBatch(bad, [enc.encode('x')], info), /^Error: PublicKey: /);
});

// from_bytes_rejects_wrong_length
test('rejects wrong lengths on every wire type', () => {
  const b = honest();
  for (const n of [0, 31, 33]) {
    const bad = b64(new Uint8Array(n));
    assert.throws(() => blindBatch(bad, [], info), /^Error: public_key: expected 32 bytes/);
    assert.throws(() => finalize({ ...b, pk: bad }), /^Error: public_key: expected 32 bytes/);
    assert.throws(() => finalize({ ...b, blinded: [bad] }), /^Error: blinded: expected 32 bytes/);
    assert.throws(() => finalize({ ...b, evaluated: [bad] }), /^Error: evaluated: expected 32 bytes/);
  }
  for (const n of [0, 63, 65]) {
    const bad = b64(new Uint8Array(n));
    assert.throws(() => finalize({ ...b, proof: bad }), /^Error: proof: expected 64 bytes/);
    // Keep a valid prefix so only the length is wrong.
    const state = fromB64(b.states[0]!);
    const sized = n <= 64 ? state.subarray(0, n) : concatBytes(state, new Uint8Array(1));
    assert.throws(() => finalize({ ...b, states: [b64(sized)] }), /^Error: state: expected 64 bytes/);
  }
});

// PoprfBlindState::from_bytes / Proof::from_bytes: deserialize_scalar rejects scalars >= l.
test('rejects non-canonical scalars in state and proof', () => {
  const b = honest();
  const ff = new Uint8Array(32).fill(0xff);
  const state = fromB64(b.states[0]!);
  assert.throws(() => finalize({ ...b, states: [b64(concatBytes(ff, state.subarray(32)))] }), decodeError);
  const proof = fromB64(b.proof);
  assert.throws(() => finalize({ ...b, proof: b64(concatBytes(ff, proof.subarray(32))) }), decodeError);
  assert.throws(() => finalize({ ...b, proof: b64(concatBytes(proof.subarray(0, 32), ff)) }), decodeError);
});

// JS-only, stricter than Rust on purpose: deserialize_scalar admits a zero blind and
// Rust then returns H(identity) garbage; noble refuses to invert zero.
test('rejects a zero blind in state', () => {
  const b = honest();
  const zeroBlind = b64(concatBytes(new Uint8Array(32), fromB64(b.states[0]!).subarray(32)));
  assert.throws(() => finalize({ ...b, states: [zeroBlind] }), /invert: expected non-zero/);
});

// finalize_rejects_tampered_proof_c, finalize_rejects_tampered_proof_s
test('rejects a tampered proof (c and s)', () => {
  for (const at of [0, 32]) {
    const b = honest();
    const proof = fromB64(b.proof);
    proof[at]! ^= 0x01; // low bit keeps the scalar canonical, so verification is what fails
    assert.throws(() => finalize({ ...b, proof: b64(proof) }), /proof verification failed/);
  }
});

// finalize_rejects_tampered_evaluated_element
test('rejects a substituted evaluated element', () => {
  const b = honest([enc.encode('input-a')]);
  const other = honest([enc.encode('input-b')]);
  assert.throws(() => finalize({ ...b, evaluated: other.blinded }), /proof verification failed/);
});

// finalize_rejects_wrong_info
test('rejects a server evaluation under a different info', () => {
  const clientInfo = enc.encode('client-different-info');
  const b = honest([enc.encode('input')], clientInfo);
  const res = ristretto255_oprf.poprf(enc.encode('server-info')).blindEvaluateBatch(server.secretKey, b.blinded.map(fromB64));
  assert.throws(() => finalize({ ...b, evaluated: res.evaluated.map(b64), proof: b64(res.proof) }), /proof verification failed/);
});

// finalize_batch_rejects_mismatched_lengths
test('rejects mismatched batch array lengths', () => {
  const b = honest();
  const lengthMismatch = /^Error: finalize_batch: array length mismatch/;
  assert.throws(() => finalize({ ...b, inputs: [...b.inputs, enc.encode('y')] }), lengthMismatch);
  assert.throws(() => finalize({ ...b, states: [...b.states, b.states[0]!] }), lengthMismatch);
  assert.throws(() => finalize({ ...b, blinded: [...b.blinded, b.blinded[0]!] }), lengthMismatch);
  assert.throws(() => finalize({ ...b, evaluated: [...b.evaluated, b.evaluated[0]!] }), lengthMismatch);
});

// JS-only: as above for blind; finalize by index must then pair each input with its own blind.
test('blinds by index, ignoring an overridden array iterator', () => {
  const inputs = [enc.encode('a'), enc.encode('b')];
  const swapped = [...inputs];
  swapped[Symbol.iterator] = () => [...inputs].reverse().values();
  const out = finalize({ ...honest(swapped), inputs });
  assert.deepEqual(out, inputs.map((x) => b64(ristretto255_oprf.poprf(info).evaluate(server.secretKey, x))));
});

// JS-only: a hole in inputs gets the input type check, not an internal TypeError.
test('rejects a sparse inputs array', () => {
  const b = honest([enc.encode('a'), enc.encode('b')]);
  const sparse = [, enc.encode('b')] as Uint8Array[];
  assert.throws(() => finalize({ ...b, inputs: sparse }), /expected Uint8Array/);
});

// JS-only: elements are read by index up to length, as in wasm, not through the array's iterator.
test('finalizes by index, ignoring an overridden array iterator', () => {
  const b = honest([enc.encode('a'), enc.encode('b')]);
  const swapped = [...b.inputs];
  swapped[Symbol.iterator] = () => [...b.inputs].reverse().values();
  assert.deepEqual(finalize({ ...b, inputs: swapped }), finalize(b));
});

// JS-only: the up-front key check must not reject a valid key with nothing to blind.
test('blinds an empty batch', () => assert.deepEqual(blindBatch(pk, [], info), { states: [], blindedMessages: [] }));

// finalize_batch_rejects_empty
test('rejects an empty finalize batch', () => {
  const b = honest();
  assert.throws(() => finalize({ ...b, inputs: [], states: [], blinded: [], evaluated: [] }), /^Error: finalize_batch: /);
});

// rejects_oversized_input_and_info: 2^16 - 1 bytes is the smallest forbidden size.
test('rejects 2^16 - 1 byte input and info', () => {
  const tooLong = new Uint8Array(0xffff).fill(0x41);
  // Not first in the batch, so every input is checked.
  assert.throws(() => blindBatch(pk, [enc.encode('a'), tooLong], info), /^Error: blind: input or info length/);
  assert.throws(() => blindBatch(pk, [enc.encode('input')], tooLong), /^Error: blind: input or info length/);
  const b = honest([enc.encode('a'), enc.encode('x')]);
  assert.throws(() => finalize({ ...b, inputs: [enc.encode('a'), tooLong] }), /^Error: finalize_batch: input or info length/);
  assert.throws(() => finalize({ ...b, info: tooLong }), /^Error: finalize_batch: input or info length/);
});

// accepts_maximum_input_and_info_lengths
test('accepts 2^16 - 2 byte input and info', () => {
  const maxOk = new Uint8Array(0xfffe).fill(0x42);
  const b = honest([maxOk], maxOk);
  assert.deepEqual(finalize(b), [b64(ristretto255_oprf.poprf(maxOk).evaluate(server.secretKey, maxOk))]);
});

// finalize_batch_rejects_mismatched_tweaked_key
test('rejects states that disagree on tweakedKey', () => {
  const a = honest([enc.encode('alpha')], enc.encode('info-a'));
  const b = honest([enc.encode('beta')], enc.encode('info-b'));
  const mixed = {
    ...a,
    inputs: [...a.inputs, ...b.inputs],
    states: [...a.states, ...b.states],
    blinded: [...a.blinded, ...b.blinded],
    evaluated: [...a.evaluated, ...b.evaluated],
  };
  assert.throws(() => finalize(mixed), mismatch);
});

// finalize_rejects_info_or_key_other_than_at_blind
test('rejects finalizing under another info or public key than at blind', () => {
  const b = honest();
  const otherPk = b64(ristretto255_oprf.poprf(info).generateKeyPair().publicKey);
  assert.throws(() => finalize({ ...b, info: enc.encode('other-info') }), mismatch);
  assert.throws(() => finalize({ ...b, pk: otherPk }), mismatch);
  // The whole tweakedKey is compared, not a prefix.
  const s = fromB64(b.states[0]!);
  s[63]! ^= 1;
  assert.throws(() => finalize({ ...b, states: [b64(s)] }), mismatch);
});

// JS-only: canonical padded base64, as the Rust STANDARD engine behind the wasm binding.
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
test('rejects malformed base64', () => {
  const b = honest();
  const good = b.blinded[0]!;
  const bad = [
    good.slice(0, -1) + '!', // bad symbol
    good.replace(/=+$/, ''), // unpadded
    ` ${good}`, // whitespace
    'AB==', // non-zero trailing bits (canonical is "AA==")
    good.slice(0, 42) + B64[B64.indexOf(good[42]!) ^ 1] + '=', // same, one pad
    'A', // length 1 mod 4
    'A===', // three pads
    `-${good.slice(1)}`, // url-safe alphabet, not only when good has a '+' or '/'
    `_${good.slice(1)}`,
  ].filter((s) => s !== good);
  assert.ok(bad.length >= 4);
  for (const s of bad) {
    assert.throws(() => blindBatch(s, [], info), /^Error: public_key base64: /);
    assert.throws(() => finalize({ ...b, pk: s }), /^Error: public_key base64: /);
    assert.throws(() => finalize({ ...b, states: [s] }), /^Error: state base64: /);
    assert.throws(() => finalize({ ...b, blinded: [s] }), /^Error: blinded base64: /);
    assert.throws(() => finalize({ ...b, evaluated: [s] }), /^Error: evaluated base64: /);
    assert.throws(() => finalize({ ...b, proof: s }), /^Error: proof base64: /);
  }
});

// JS-only: a huge value fails our length check, not with a stack overflow.
test('rejects oversized base64', () => {
  const b = honest();
  const huge = 'AAAA'.repeat(250_000);
  assert.throws(() => blindBatch(huge, [], info), /^Error: public_key: /);
  assert.throws(() => finalize({ ...b, proof: huge }), /^Error: proof: /);
  assert.throws(() => finalize({ ...b, states: [huge] }), /^Error: state: /);
});

// JS-only, stricter than wasm on purpose: wasm coerces array-likes.
test('rejects non-Uint8Array inputs and info', () => {
  const b = honest();
  for (const v of [[1, 2, 3], 'abc', 42, null, undefined, new Uint16Array(2)]) {
    const x = v as unknown as Uint8Array;
    assert.throws(() => blindBatch(pk, [x], info), /expected Uint8Array/);
    assert.throws(() => blindBatch(pk, [enc.encode('a')], x), /expected Uint8Array/);
    assert.throws(() => finalize({ ...b, inputs: [x] }), /expected Uint8Array/);
    assert.throws(() => finalize({ ...b, info: x }), /expected Uint8Array/);
  }
  // wasm would read a non-array's missing `.length` as an empty batch.
  assert.throws(() => blindBatch(pk, new Set([enc.encode('a')]) as unknown as Uint8Array[], info), /inputs must be an array/);
  for (const k of ['inputs', 'states', 'blinded', 'evaluated'] as const) {
    assert.throws(() => finalize({ ...b, [k]: new Set<unknown>(b[k]) as never }), /^Error: finalize_batch: arrays expected/);
  }
});

// JS-only, mirrors wasm's "<name> must be string" for the string arrays.
test('rejects non-string state, blinded and evaluated elements', () => {
  const b = honest();
  for (const v of [fromB64(b.states[0]!), 42, null, ['AAAA'], { length: 4 }]) {
    const x = v as unknown as string;
    assert.throws(() => finalize({ ...b, states: [x] }), /^Error: state must be string/);
    assert.throws(() => finalize({ ...b, blinded: [x] }), /^Error: blinded must be string/);
    assert.throws(() => finalize({ ...b, evaluated: [x] }), /^Error: evaluated must be string/);
  }
});
