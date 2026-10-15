import { Request, Response } from 'express';

const tracks: string[] = [];

export function remove(req: Request, res: Response) {
  const pos = +req.body.position;
~>  tracks.splice(pos, 1);
  res.sendStatus(204);
}

export function get(req: Request, res: Response) {
~>  res.json(tracks[parseInt(req.query.idx as string, 10)]);
}

export function at(req: Request, res: Response) {
~>  res.json(tracks.at(Number(req.params.slot)));
}
