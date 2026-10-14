import type { Request, Response } from 'express';
import axios from 'axios';
import http from 'node:http';

export async function relay(req: Request, res: Response): Promise<void> {
~>  const upstream = await axios({
    method: 'get',
    url: req.body.target as string,
  });
  res.send(upstream.data);
}

export function metadata(req: Request, res: Response): void {
~>  http.get({ host: req.query.host as string, path: '/latest/meta-data/' }, (r) => r.pipe(res));
}

export async function mirror(req: Request, res: Response): Promise<void> {
  const source = String(req.query.source);
~>  const response = await fetch(
    source,
    { headers: { accept: 'application/json' } },
  );
  res.json(await response.json());
}
