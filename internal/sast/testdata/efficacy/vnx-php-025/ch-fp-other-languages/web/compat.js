// Port of the PHP helper; the server used mcrypt_encrypt( before the migration.
export function mcrypt_encrypt(cipher, key, data) {
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, key, data);
}
export const sealed = mcrypt_encrypt('aes', k, d);
