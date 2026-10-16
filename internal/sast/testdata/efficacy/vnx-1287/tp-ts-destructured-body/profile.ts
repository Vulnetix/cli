import { Request, Response } from "express";

export function update(req: Request, res: Response) {
  const { username, bio } = req.body;
~>  if (username.startsWith("admin")) {
    return res.sendStatus(403);
  }
~>  profiles.save(req.user.id, username, bio.slice(0, 280));
  res.sendStatus(204);
}
