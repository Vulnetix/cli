import { createDecipher as legacyDecipher, randomBytes } from 'node:crypto';

export function open(blob, secret) {
~>  const d = legacyDecipher('des-ede3-cbc', secret);
  return Buffer.concat([d.update(blob), d.final()]);
}

export const nonce = () => randomBytes(12);
