import * as nodeCrypto from 'crypto';

export function decrypt(hex: string, pw: string) {
~>  const d = nodeCrypto.createDecipher('aes192', pw);
  return d.update(hex, 'hex', 'utf8') + d.final('utf8');
}
