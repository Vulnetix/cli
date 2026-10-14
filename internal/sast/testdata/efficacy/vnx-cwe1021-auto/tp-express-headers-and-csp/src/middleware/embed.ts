import type { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';

export function allowEmbedding(_req: Request, res: Response, next: NextFunction): void {
~>  res.setHeader('X-Frame-Options', 'ALLOWALL');
  next();
}

export function stripFrameHeader(_req: Request, res: Response, next: NextFunction): void {
~>  res.removeHeader("X-Frame-Options");
  next();
}

export const csp = helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
~>    frameAncestors: ["*"],
    imgSrc: ["'self'", 'data:'],
  },
});

export function headers(res: Response): void {
~>  res.set({ 'Content-Security-Policy': `default-src 'self'; frame-ancestors https:` });
}
