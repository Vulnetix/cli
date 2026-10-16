import * as crypto from 'crypto';
import jwt from 'jsonwebtoken';

// Each literal key below is reported once, by VNX-NODE-019.
const WEBHOOK_HMAC_KEY = '@@sample:Q[7]w[e]R[t]Y[u]8[i]O[p]2[a]S[d]F[g]H[j]@@';

export const settings = {
  jwt_secret: '@@sample:k[2]J[h]G[f]D[s]A[9]L[z]X[c]V[b]N[m]4[q]@@',
};

export function verify(token: string) {
  return jwt.verify(token, '@@sample:P[o]I[u]Y[t]R[e]W[q]5[l]K[j]H[g]F[d]@@');
}

export function signBody(alg: string, body: string) {
  return crypto.createHmac(alg, 'hmac-key-material-0099').update(body).digest('hex');
}

export function signWebhook(body: string) {
  return crypto.createHmac('sha256', WEBHOOK_HMAC_KEY).update(body).digest('hex');
}
