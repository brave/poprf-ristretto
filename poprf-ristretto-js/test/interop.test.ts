// JS <-> wasm (the Rust client) in both directions, with noble as an independent server.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import * as js from '../src/index.ts';
import { b64, fromB64 } from './util.ts';

const wasm = createRequire(import.meta.url)('../../poprf-ristretto-wasm/pkg-node/poprf_ristretto_wasm.js') as typeof js;

const impls = { js, wasm };
for (const [b, f] of [['js', 'wasm'], ['wasm', 'js']] as const) {
  const name = `${b} blind -> ${f} finalize`;
  for (const n of [1, 30]) {
    for (const info of [new Uint8Array(), new TextEncoder().encode('info')]) {
      test(`${name} (batch ${n}, info ${info.length}B)`, () => {
        const poprf = ristretto255_oprf.poprf(info);
        const { secretKey, publicKey } = poprf.generateKeyPair();
        const pk = b64(publicKey);
        // Lengths 0..n-1 cover the empty input.
        const inputs = Array.from({ length: n }, (_, j) => new Uint8Array(j).fill(j));
        const { states, blindedMessages } = impls[b].blindBatch(pk, inputs, info);
        const { evaluated, proof } = poprf.blindEvaluateBatch(secretKey, blindedMessages.map(fromB64));
        const finalize = (p: string) => impls[f].finalizeBatch(pk, inputs, states, blindedMessages, evaluated.map(b64), p, info);
        assert.deepEqual(finalize(b64(proof)), inputs.map((input) => b64(poprf.evaluate(secretKey, input))));
        proof[0]! ^= 1;
        // RegExp also matches wasm's bare-string throws.
        assert.throws(() => finalize(b64(proof)), /proof verification failed/);
      });
    }
  }
}
