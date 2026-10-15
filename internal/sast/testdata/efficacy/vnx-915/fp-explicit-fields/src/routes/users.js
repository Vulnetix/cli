const _ = require('lodash');

router.put('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, _.pick(req.body, ['name', 'bio']));
  await User.create({ name: req.body.name, email: req.body.email });
  const opts = Object.assign({}, defaults, req.query);
  res.json(user);
});
