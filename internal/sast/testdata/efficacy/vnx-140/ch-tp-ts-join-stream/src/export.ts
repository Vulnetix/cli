import { createWriteStream } from 'fs';
import { Request, Response } from 'express';

const out = createWriteStream('report.tsv', { flags: 'a' });

export function track(req: Request, res: Response) {
  const row = [req.query.page, req.query.ref].join('\t');
~>  out.write(row + '\n');
  res.sendStatus(204);
}
