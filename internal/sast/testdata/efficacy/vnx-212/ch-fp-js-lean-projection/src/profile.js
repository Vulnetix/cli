const { User } = require('./models');

async function show(req, res) {
  const user = await User.findById(req.params.id).lean();
  res.json({ id: user._id, name: user.name, avatar: user.avatar });
}

async function list(req, res) {
  const users = await User.find({}, 'name email');
  res.json(users);
}

module.exports = { show, list };
