import type { Request, Response } from 'express';
import nunjucks from 'nunjucks';

const env = new nunjucks.Environment();

export function banner(req: Request, res: Response): void {
~>  const html = env.renderString('<h1>' + req.query.title + '</h1>', {});
  res.send(html);
}

export function note(req: Request, res: Response): void {
  const text = req.body.text as string;
~>  res.send(nunjucks.renderString(`<p>${text}</p>`, { user: req.user }));
}
