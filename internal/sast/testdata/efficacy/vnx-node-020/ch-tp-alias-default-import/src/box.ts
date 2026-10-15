import nodeCrypto from 'crypto';

export function seal(data: Buffer, key: string): Buffer {
  const c = nodeCrypto
~>    .createCipher('aes192', key);
  return Buffer.concat([c.update(data), c.final()]);
}
