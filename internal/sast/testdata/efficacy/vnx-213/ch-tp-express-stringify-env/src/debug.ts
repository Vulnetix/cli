import { Router } from 'express';

export const debug = Router();

debug.get('/debug/env', (_req, res) => {
  res.type('text/plain');
~>  res.send(JSON.stringify(process.env, null, 2));
});
