import { createCipheriv, pbkdf2Sync } from 'crypto';

export function encryptToken(key: Buffer, token: string): string {
~>  const cipher = createCipheriv('aes-256-cbc', key, Buffer.alloc(16, 0));
  return cipher.update(token, 'utf8', 'hex') + cipher.final('hex');
}

export function deriveKey(password: string): Buffer {
~>  return pbkdf2Sync(password, 'static-app-salt', 100000, 32, 'sha256');
}
