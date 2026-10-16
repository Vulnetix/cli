import { Request, Response } from 'express';

export function listByTags(req: Request, res: Response) {
  const { tags } = req.query;
~>  const list = tags.split(',');
  res.json(repo.byTags(list));
}
