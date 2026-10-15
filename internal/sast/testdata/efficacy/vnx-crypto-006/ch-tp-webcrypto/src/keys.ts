export async function makeKey() {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
~>      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
}

export const sign = () =>
~>  crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 512, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"]);
