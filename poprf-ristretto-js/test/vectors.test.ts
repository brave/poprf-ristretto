// RFC 9497 Appendix A POPRF vectors, read from the Rust crate's copy so both
// implementations are held to the same file.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { bytesToHex, concatBytes } from '@noble/curves/utils.js';
import { finalizeBatch } from '../src/index.ts';
import { b64, fromB64, hex } from './util.ts';

type Vector = {
  BatchSize: number;
  Input: string[];
  Info: string;
  Blind: string[];
  BlindedElement: string[];
  EvaluationElement: string[];
  Output: string[];
  Proof: string;
};
type Mode = { pkSm: string; vectors: Vector[] };

const file = new URL('../../poprf-ristretto/tests/vectors/ristretto255-SHA512.json', import.meta.url);
const mode: Mode = JSON.parse(readFileSync(file, 'utf8')).modes.POPRF;

const pk = b64(hex(mode.pkSm));
for (const [i, v] of mode.vectors.entries()) {
  const inputs = v.Input.map(hex);
  const info = hex(v.Info);

  test(`vector ${i}: finalizeBatch reproduces Output (batch ${v.BatchSize})`, () => {
    // tweakedKey depends only on (pk, info); take it from any noble blind.
    const tweakedKey = ristretto255_oprf.poprf(info).blind(new Uint8Array(), hex(mode.pkSm)).tweakedKey;
    const states = v.Blind.map((blind) => b64(concatBytes(hex(blind), tweakedKey)));
    const out = finalizeBatch(
      pk,
      inputs,
      states,
      v.BlindedElement.map((h) => b64(hex(h))),
      v.EvaluationElement.map((h) => b64(hex(h))),
      b64(hex(v.Proof)),
      info,
    );
    assert.deepEqual(out.map((o) => bytesToHex(fromB64(o))), v.Output);
  });
}

test('vectors file has the POPRF batches', () => {
  assert.ok(mode.vectors.length >= 3);
  assert.ok(mode.vectors.some((v) => v.BatchSize > 1));
});
