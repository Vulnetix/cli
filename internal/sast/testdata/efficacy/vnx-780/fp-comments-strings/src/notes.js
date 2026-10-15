// Do not use padding: crypto.constants.RSA_PKCS1_PADDING with publicEncrypt.
/* openssl_public_encrypt($data, $out, $key) defaults to PKCS#1 v1.5 */
const tip = "set encryptionScheme: 'pkcs1' only for interop";
module.exports = tip;
