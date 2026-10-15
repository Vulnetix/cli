const ALLOWED_TRANSITIONS = { pending: ['paid', 'cancelled'], paid: ['shipped'] };

router.post('/orders/:id/status', async (req, res) => {
  const order = await Order.findById(req.params.id);
  const wanted = req.body.status;
  if (!ALLOWED_TRANSITIONS[order.status].includes(wanted)) {
    return res.status(409).json({ error: 'invalid transition' });
  }
  order.status = wanted;
  await order.save();
  res.json(order);
});
