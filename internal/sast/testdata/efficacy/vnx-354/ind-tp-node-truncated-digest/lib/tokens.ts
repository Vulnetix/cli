import { createHash } from 'node:crypto';

export function checkShareToken(docId: string, token: string): boolean {
  const digest = createHash('sha256')
    .update(`${docId}:${process.env.SHARE_SALT}`)
    .digest('hex');
~>  return digest.slice(0, 12) === token;
}
