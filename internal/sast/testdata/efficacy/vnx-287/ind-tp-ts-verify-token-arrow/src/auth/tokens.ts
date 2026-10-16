import type { Request } from 'express';

export interface TokenClaims {
  sub: string;
  scope: string[];
}

~>export const verifyToken = (token: string): boolean => true;

export function bearerFrom(req: Request): string | undefined {
  const h = req.headers.authorization;
  return h?.startsWith('Bearer ') ? h.slice(7) : undefined;
}
