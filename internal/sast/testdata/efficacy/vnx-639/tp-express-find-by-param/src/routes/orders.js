const Order = require('../models/order');

router.get('/orders/:id', async (req, res) => {
~>  const order = await Order.findById(req.params.id);
  res.json(order);
});

router.delete('/invoices/:id', async (req, res) => {
~>  await Invoice.destroy({ where: { id: req.params.id } });
  res.status(204).end();
});

router.get('/wallet', async (req, res) => {
~>  const wallet = await WalletModel.findOne({ where: { UserId: req.query.UserId } });
  res.json(wallet);
});
