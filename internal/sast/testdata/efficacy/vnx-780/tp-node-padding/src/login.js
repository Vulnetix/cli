import { JSEncrypt } from "jsencrypt";

export function encryptPassword(publicKeyPem, password) {
~>  const enc = new JSEncrypt();
  enc.setPublicKey(publicKeyPem);
  return enc.encrypt(password);
}
