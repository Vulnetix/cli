import { Request, Response } from 'express';

export async function locale(req: Request, res: Response) {
  const lang = req.headers['x-lang'];
~>  const mod = await import(`./locales/${lang}.js`);
  res.json(mod.default);
}
