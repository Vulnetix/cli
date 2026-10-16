import type { Request } from 'express';

export function generateSessionId(): string {
~>  return Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString(16);
}

export function attach(req: Request): void {
  (req as any).sid = generateSessionId();
}
