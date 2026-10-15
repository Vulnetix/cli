import { createHash } from "crypto";
import { Request, Response } from "express";

export async function login(req: Request, res: Response) {
  const user = await users.findOne({ email: req.body.email });
~>  if (!user || req.body.password !== user.password) {
    return res.status(401).end();
  }
  res.json({ ok: true });
}

export function checkHash(account: Account, input: string): boolean {
~>  const ok = account.passwordHash === createHash("sha1").update(input).digest("hex");
  return ok;
}
