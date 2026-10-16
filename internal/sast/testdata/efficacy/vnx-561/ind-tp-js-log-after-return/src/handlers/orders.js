const logger = require('../logger');

async function cancelOrder(req, res) {
  const order = await req.db.orders.findById(req.params.id);
  if (order.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'not your order' });
~>    logger.warn('cancel attempt by non-owner', { user: req.user.id, order: order.id });
  }
  await order.cancel();
  res.json({ ok: true });
}

module.exports = { cancelOrder };
