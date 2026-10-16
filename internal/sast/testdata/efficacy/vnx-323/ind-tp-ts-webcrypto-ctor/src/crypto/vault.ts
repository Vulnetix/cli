export class Vault {
  private readonly iv: Uint8Array;

  constructor(private readonly key: CryptoKey) {
    this.iv = crypto.getRandomValues(new Uint8Array(12));
  }

  async encrypt(data: Uint8Array): Promise<ArrayBuffer> {
~>    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: this.iv }, this.key, data);
  }
}
