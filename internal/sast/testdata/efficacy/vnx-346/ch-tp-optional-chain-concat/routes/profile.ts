import type { Request, Response } from "express";

export function updateProfile(req: Request, res: Response, host: string) {
~>  const sameOrigin = req.headers.origin?.includes("://" + host) ??
~>    req.headers.referer?.includes(host)
  if (!sameOrigin) {
    return res.status(403).end();
  }
~>  if (req.headers.referer?.startsWith("https://app.example.com")) {
    save(req.body);
  }
}
