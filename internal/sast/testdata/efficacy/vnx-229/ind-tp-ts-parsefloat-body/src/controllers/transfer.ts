import { Request, Response } from "express";

export async function transfer(req: Request, res: Response) {
~>  const amount = parseFloat(req.body.amount);
  const from = await Account.findById(req.user.id);
  from.balance -= amount;
  await from.save();
  res.json({ balance: from.balance });
}
