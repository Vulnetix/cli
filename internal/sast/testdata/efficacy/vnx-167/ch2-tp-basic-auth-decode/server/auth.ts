import { Request, Response, NextFunction } from 'express';

export function basicAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Basic\s+/i, '');
~>  const [username, password] = Buffer.from(token, 'base64').toString('utf8').split(':');
  if (!checkUser(username, password)) {
    return res.status(401).end();
  }
  next();
}

declare function checkUser(u: string, p: string): boolean;
