import { Request, Response } from 'express';

export function setLang(req: Request, res: Response) {
  const lang = req.query.lang as string;
  const { callback } = req.body;
~>  res.setHeader('Content-Language', lang);
~>  res.set({ 'X-Callback': callback });
  res.end();
}
