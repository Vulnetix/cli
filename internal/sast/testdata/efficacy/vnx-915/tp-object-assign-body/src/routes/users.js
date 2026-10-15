const User = require('../models/user');

router.put('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
~>  Object.assign(user, req.body);
  await user.save();
  res.json(user);
});
