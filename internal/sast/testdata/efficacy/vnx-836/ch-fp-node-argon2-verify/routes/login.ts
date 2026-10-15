import argon2 from 'argon2';
import { Request, Response } from 'express';
import { users } from '../db';

export async function login(req: Request, res: Response) {
  const user = await users.byEmail(req.body.email);
  const ok = await argon2.verify(user.passwordHash, req.body.password);
  if (!ok) {
    return res.status(401).end();
  }
  const rehashed = user.passwordHash === user.legacyPasswordHash;
  return res.json({ ok, rehashed });
}
