import { Request, Response } from 'express';

export async function getOrder(req: Request, res: Response) {
  const order = await Orders.findOne({ id: req.params.id });
~>  if (!order) res.status(404).send('missing');
  res.json(order);
}
