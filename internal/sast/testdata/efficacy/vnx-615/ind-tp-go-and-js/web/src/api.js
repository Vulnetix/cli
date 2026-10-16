import axios from 'axios';

/*
 * Internal metrics API.
~> * auth_token = "mt-2291-delta-x"
 */
export const metrics = axios.create({
  baseURL: '/api/metrics',
  headers: { Authorization: `Bearer ${window.__METRICS_TOKEN__}` },
});

~>// const passphrase = 'blue-Horse-42!';
export function decrypt(blob, passphrase) {
  return window.crypto.subtle.decrypt({ name: 'AES-GCM' }, passphrase, blob);
}
