// The built package under `node --jitless` (no WebAssembly), the runtime it exists for.
import assert from 'node:assert/strict';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { blindBatch, finalizeBatch } from '../dist/index.js';

assert.equal(typeof WebAssembly, 'undefined', 'run with node --jitless');
const b64 = (b) => Buffer.from(b).toString('base64');
const info = new TextEncoder().encode('info');
const input = new TextEncoder().encode('input');
const poprf = ristretto255_oprf.poprf(info);
const { secretKey, publicKey } = poprf.generateKeyPair();
const { states, blindedMessages } = blindBatch(b64(publicKey), [input], info);
const { evaluated, proof } = poprf.blindEvaluateBatch(secretKey, blindedMessages.map((s) => new Uint8Array(Buffer.from(s, 'base64'))));
const outputs = finalizeBatch(b64(publicKey), [input], states, blindedMessages, evaluated.map(b64), b64(proof), info);
assert.deepEqual(outputs, [b64(poprf.evaluate(secretKey, input))]);
console.log('jitless ok');
