import { createCipheriv, randomBytes } from 'crypto';

export class Crypter {
  private readonly iv = randomBytes(12);

  constructor(private readonly key: Buffer) {}

  encrypt(text: string): Buffer {
~>    const cipher = createCipheriv('aes-256-gcm', this.key, this.iv);
    return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  }
}
