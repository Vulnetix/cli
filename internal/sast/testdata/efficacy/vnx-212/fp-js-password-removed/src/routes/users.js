const User = require('../models/user');

router.get('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id).select('-password');
  res.json(user);
});

router.get('/members/:id', async (req, res) => {
  const member = await User.findByPk(req.params.id, {
    attributes: { exclude: ['password', 'resetToken'] },
  });
  res.json(member);
});

router.get('/me', async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  delete me.password;
  res.json(me);
});

router.get('/public/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user.toPublicJSON());
});

router.get('/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

router.get('/safe/:id', async (req, res) => {
  const found = await User.findById(req.params.id);
  const { password, ...safe } = found.toObject();
  res.json(safe);
});
