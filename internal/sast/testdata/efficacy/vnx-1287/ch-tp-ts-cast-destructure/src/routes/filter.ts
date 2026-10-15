import { Request, Response } from "express";

export function listProducts(req: Request, res: Response) {
  const { tags } = req.query as { tags: string };
~>  const wanted = tags.split(",");
  const sort = req.query.sort as string;
~>  if (sort.startsWith("-")) {
    res.json({ wanted, desc: true });
    return;
  }
  res.json({ wanted });
}
