import type { Request, Response } from 'express';
import { exec } from 'node:child_process';

export function lookup(req: Request, res: Response): void {
  const host = req.query.host as string;
~>  exec(`nslookup ${host}`, (err, stdout) => {
    res.type('text/plain').send(stdout);
  });
}
