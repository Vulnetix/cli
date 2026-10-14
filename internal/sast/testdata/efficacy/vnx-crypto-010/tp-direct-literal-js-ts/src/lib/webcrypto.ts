export async function encryptBlob(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
~>  return crypto.subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12) }, key, data);
}

export async function encryptCbc(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt(
    {
      name: "AES-CBC",
~>      iv: new TextEncoder().encode("static-iv-123456"),
    },
    key,
    data,
  );
}
