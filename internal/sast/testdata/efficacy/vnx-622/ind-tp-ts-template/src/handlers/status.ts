import { Request, Response } from 'express';
import { getStatus } from '../status';

export async function statusJsonp(req: Request, res: Response) {
  const callbackName = req.query.jsonp as string;
  const payload = JSON.stringify(await getStatus());
  res.type('text/javascript');
~>  res.send(`${callbackName}(${payload});`);
}
