import * as crypto from 'crypto';
import jwt from 'jsonwebtoken';

~>const JWT_SECRET = 'a9f3c1e7b2d4';

export function signWebhook(body: string): string {
~>  return crypto.createHmac('sha256', '@@sample:w[e]bh[o]ok[-]si[g]ni[n]g[-][k]ey[-]20[2]4@@').update(body).digest('hex');
}

export function issue(userId: string): string {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '1h' });
}
