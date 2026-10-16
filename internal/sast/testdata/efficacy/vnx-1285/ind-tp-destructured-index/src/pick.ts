import { Request, Response } from 'express';

export function pick(req: Request, res: Response) {
  const { index } = req.body;
~>  res.json(choices[index]);
}
