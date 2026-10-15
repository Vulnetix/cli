import { Router } from 'express';
import { charge } from '../billing';

export const payments = Router();

payments.post('/pay', async (req, res) => {
  const {
    orderId,
~>    totalPrice,
  } = req.body;
  await charge(req.user.id, orderId, totalPrice);
  res.sendStatus(204);
});
