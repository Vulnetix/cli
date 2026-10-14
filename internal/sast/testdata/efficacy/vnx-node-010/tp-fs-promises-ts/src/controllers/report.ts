import type { Request, Response } from 'express';
import { readFile } from 'node:fs/promises';
import * as fsp from 'fs/promises';

const ROOT = '/srv/reports';

export async function getReport(req: Request, res: Response): Promise<void> {
~>  const text = await readFile(`${ROOT}/${req.params.doc}`, 'utf8');
  res.type('text/plain').send(text);
}

export async function purge(req: Request, res: Response): Promise<void> {
  const dir = req.body.dir as string;
~>  await fsp.rm(ROOT + '/' + dir, { recursive: true });
  res.sendStatus(204);
}
