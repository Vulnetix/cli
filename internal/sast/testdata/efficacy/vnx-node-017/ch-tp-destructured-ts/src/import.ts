import { Request, Response } from 'express';
const { unserialize } = require('node-serialize');

export async function importSettings(req: Request, res: Response): Promise<void> {
  const payload: string = req.body.settings as string;
~>  const settings = unserialize(payload);
  res.json({ ok: true, keys: Object.keys(settings) });
}
