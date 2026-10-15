import { Request, Response } from 'express';

export async function grant(req: Request, res: Response) {
~>  await Wallet.updateOne({ owner: req.params.user }, { $inc: { credits: req.body.credits } });
  res.sendStatus(204);
}
