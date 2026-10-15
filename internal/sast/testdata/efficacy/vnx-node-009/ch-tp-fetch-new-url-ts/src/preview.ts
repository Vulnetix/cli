import type { Request, Response } from 'express';

export async function linkPreview(req: Request, res: Response) {
  const dest = new URL(String(req.query.url));
~>  const page = await fetch(dest, { redirect: 'follow' });
  const html = await page.text();
  res.send({ title: html.match(/<title>(.*?)<\/title>/)?.[1] });
}
