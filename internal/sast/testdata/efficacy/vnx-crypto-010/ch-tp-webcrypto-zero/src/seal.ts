export async function seal(key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt(
~>    { name: 'AES-GCM', iv: new Uint8Array(12) },
    key,
    data,
  );
}
