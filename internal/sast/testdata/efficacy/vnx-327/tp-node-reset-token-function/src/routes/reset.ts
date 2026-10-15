import crypto from 'crypto';

export function generateResetToken(email: string): string {
~>  return crypto.createHash("sha1").update(email + Date.now()).digest("hex");
}

export const signature = (body: string) =>
  crypto
~>    .createHash('md5')
    .update(body + SECRET)
    .digest('hex');
