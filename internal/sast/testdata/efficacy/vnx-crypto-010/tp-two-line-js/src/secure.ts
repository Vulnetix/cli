import crypto from "node:crypto";

~>const IV = Buffer.from("00112233445566778899aabbccddeeff", "hex");

export function seal(text: string, key: Buffer): string {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, IV);
  return cipher.update(text, "utf8", "hex") + cipher.final("hex");
}

export function hashPassword(password: string): Buffer {
~>  return crypto.pbkdf2Sync(password, "static-salt", 310000, 32, "sha256");
}

export async function deriveAesKey(pass: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
~>    { name: "PBKDF2", salt: new TextEncoder().encode("my-app-salt"), iterations: 100000, hash: "SHA-256" },
    pass,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptRecord(key: CryptoKey, data: Uint8Array) {
~>  const iv = new Uint8Array(12);
  return crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
}

export function legacyEncrypt(text: string, key: Buffer) {
~>  const nonce = Buffer.alloc(16, 0);
  const c = crypto.createCipheriv('aes-128-ctr', key, nonce);
  return Buffer.concat([c.update(text), c.final()]);
}
