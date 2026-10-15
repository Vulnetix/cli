import { Request, Response } from "express";

export function me(req: Request, res: Response) {
~>  const profile = JSON.parse(
    Buffer.from(req.cookies.profile, "base64").toString("utf8")
  );
  res.json({ role: profile.role });
}
