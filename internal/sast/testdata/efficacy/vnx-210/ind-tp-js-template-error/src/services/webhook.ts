import crypto from 'node:crypto';

export function verifyWebhook(payload: string, signature: string, webhookSecret: string): void {
  const expected = crypto.createHmac('sha256', webhookSecret).update(payload).digest('hex');
  if (expected !== signature) {
~>    throw new Error(`signature mismatch using secret ${webhookSecret}`);
  }
}
