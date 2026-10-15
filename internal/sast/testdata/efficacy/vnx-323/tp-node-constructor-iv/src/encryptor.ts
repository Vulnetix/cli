import { createCipheriv, randomBytes } from 'crypto';

export class Encryptor {
  private iv: Buffer;

  constructor(private key: Buffer) {
    this.iv = randomBytes(12);
  }

  encrypt(text: string): string {
~>    const cipher = createCipheriv('aes-256-gcm', this.key, this.iv);
    return cipher.update(text, 'utf8', 'base64') + cipher.final('base64');
  }
}
