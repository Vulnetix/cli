import { Request, Response, NextFunction } from 'express';

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  if (req.cookies.isAdmin === 'true') {
    return next();
  }
  res.status(403).json({ error: 'forbidden' });
}

export function requireEditor(req: Request, res: Response, next: NextFunction) {
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  const role = req.cookies['user_role'];
  if (role === 'editor' || role === 'admin') {
    return next();
  }
  res.sendStatus(403);
}

export function audit(req: Request) {
~>  const { role, lang } = req.cookies;
  console.log(role, lang);
}
