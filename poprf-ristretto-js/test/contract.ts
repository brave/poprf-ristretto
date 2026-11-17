// Compile-time only: fails tsc if the JS and wasm signatures of blindBatch/finalizeBatch drift apart.
import type * as Wasm from '../../poprf-ristretto-wasm/pkg-node/poprf_ristretto_wasm.js';
import type * as Js from '../src/index.ts';

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
const assertEqual = <T extends true>() => {};

assertEqual<Equal<typeof Js.blindBatch, typeof Wasm.blindBatch>>();
assertEqual<Equal<typeof Js.finalizeBatch, typeof Wasm.finalizeBatch>>();
