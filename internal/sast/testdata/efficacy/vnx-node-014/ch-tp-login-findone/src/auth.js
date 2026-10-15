const User = require('../models/user');

exports.login = async (req, res) => {
~>  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  if (!user) return res.status(401).end();
  res.json({ id: user.id });
};
