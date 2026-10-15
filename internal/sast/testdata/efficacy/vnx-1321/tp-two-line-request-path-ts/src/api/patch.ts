import { Request, Response } from 'express';

const documents: Record<string, any> = {};

export function patchDocument(req: Request, res: Response) {
  const { id } = req.params;
  const field: string = req.body.field;
  const sub = req.body.sub;
~>  documents[field][sub] = req.body.value;
  res.json(documents[id]);
}
