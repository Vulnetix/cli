import CryptoJS from "crypto-js";

export function hashPassword(password) {
~>  return CryptoJS.MD5(password).toString();
}

export function signRequest(secret, body) {
~>  const signature = CryptoJS.SHA1(secret + body).toString(CryptoJS.enc.Hex);
  return signature;
}

export function cacheKey(url) {
  return CryptoJS.MD5(url).toString();
}
