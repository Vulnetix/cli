import { Request, Response } from "express";

export function listUsers(req: Request, res: Response) {
~>  const includeDeleted = Boolean(req.query.include_deleted);
  res.json(repo.list({ includeDeleted }));
}
