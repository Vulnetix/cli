import { XMLParser } from 'fast-xml-parser';
import { Request, Response } from 'express';

export function upload(req: Request, res: Response) {
  const parser = new XMLParser();
~>  const doc = parser.parse(req.body as string);
  res.json(doc);
}
