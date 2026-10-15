import { Request, Response } from 'express';
import { CartItem } from '../models';

export async function addToCart(req: Request, res: Response) {
  const qty: number = Number(req.body.qty);
  const item = await CartItem.findByPk(req.body.itemId);
~>  item.subtotal = item.price * qty;
  await item.save();
  res.json(item);
}
