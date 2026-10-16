import { Request, Response, NextFunction } from 'express';

export function isSafeHref(href: string): boolean {
  const value = href.trim();
~>  if (value.includes('javascript:') || value.includes('vbscript:')) {
    return false;
  }
  return true;
}

export function stripHandlers(markup: string): string {
~>  const handlerPattern = new RegExp('onload\\s*=\\s*"[^"]*"', 'g');
  return markup.replace(handlerPattern, '');
}

export function linkGuard(req: Request, res: Response, next: NextFunction) {
  if (!isSafeHref(String(req.body.url || ''))) {
    return res.status(400).json({ error: 'invalid link' });
  }
  req.body.bio = stripHandlers(String(req.body.bio || ''));
  next();
}
