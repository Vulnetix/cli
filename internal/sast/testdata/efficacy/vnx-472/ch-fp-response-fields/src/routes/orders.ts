import { Router } from 'express';

export const orders = Router();

orders.get('/orders/:id', async (req, res) => {
  const order = await loadOrder(req.params.id);
  res.json({ total: order.total, price: order.price, role: req.user.role });
});
