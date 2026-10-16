import { Request, Response } from 'express';
import { cartTotal } from './cart';

export async function checkout(req: Request, res: Response) {
  const subtotal = await cartTotal(req.session.cartId);
~>  const discount = Number(req.query.discount);
  const charge = subtotal - discount;
  res.json({ charge });
}
