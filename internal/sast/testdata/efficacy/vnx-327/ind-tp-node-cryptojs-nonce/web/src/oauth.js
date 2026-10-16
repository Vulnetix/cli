import CryptoJS from 'crypto-js';

export function buildAuthorizeUrl(clientId, redirectUri) {
~>  const nonce = CryptoJS.MD5(String(Date.now()) + clientId).toString();
  const params = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, nonce });
  return `https://auth.example.com/authorize?${params}`;
}
