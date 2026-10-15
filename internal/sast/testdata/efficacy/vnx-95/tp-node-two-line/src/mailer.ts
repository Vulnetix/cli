import * as ejs from 'ejs';
import { Request, Response } from 'express';

export async function preview(req: Request, res: Response) {
  const { subject } = req.body;
  const source = '<h2>' + subject + '</h2>';
~>  const html = ejs.render(
    source,
    { name: 'x' }
  );
  res.send(html);
}
