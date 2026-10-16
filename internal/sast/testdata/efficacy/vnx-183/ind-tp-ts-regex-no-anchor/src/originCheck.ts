import type { Request } from 'express';

export function isTrustedOrigin(req: Request): boolean {
  const origin = req.headers.origin ?? '';
~>  return /acme\.com$/.test(origin);
}
