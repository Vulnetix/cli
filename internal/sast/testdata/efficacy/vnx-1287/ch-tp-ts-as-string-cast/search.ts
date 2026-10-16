import { Request, Response } from "express";

export function search(req: Request, res: Response) {
  const term = req.query.q as string;
~>  const words = term.split(" ");
  res.json({ words });
}
