import { Request, Response } from "express";

export async function create(req: Request, res: Response) {
  const { quantity, note } = req.body;
  const qtyRaw = req.body.qty;
~>  const qty = parseFloat(qtyRaw);
~>  const units = Number(quantity);
  await orders.insert({ sku: req.body.sku, qty, units, note });
  res.sendStatus(201);
}
