import { Request, Response } from 'express';

export async function getOrder(req: Request, res: Response) {
  const order = await orders.find(req.params.id);
~>  if (!order) res.status(404).send('missing');
  res.json(order);
}

export function update(req: Request, response: Response) {
  if (!req.body) {
~>    response.status(400).end();
  }
  response.status(200).json({ ok: true });
}
