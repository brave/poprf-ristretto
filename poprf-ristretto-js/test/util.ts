// Shared test codecs; Node's Buffer is fine here (src stays browser-only).
export const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
export const fromB64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
export { hexToBytes as hex } from '@noble/curves/utils.js';
