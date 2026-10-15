import type { Request, Response } from 'express';

export async function messages(req: Request, res: Response) {
  const lang = req.headers['accept-language'];
~>  const mod = await import(`./locales/${lang}.js`);
  res.json(mod.default);
}

export async function widget(request: Request, res: Response) {
~>  const w = await import(
    '../widgets/' + request.query.widget
  );
  res.json(w);
}
