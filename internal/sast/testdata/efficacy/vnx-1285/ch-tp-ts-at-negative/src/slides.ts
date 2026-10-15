import { Request, Response } from 'express';

const slides: string[] = ['intro', 'pricing', 'internal-roadmap'];

export function slide(req: Request, res: Response) {
  const slot = Number.parseInt(String(req.query.slot), 10);
~>  res.send(slides.at(slot));
}
