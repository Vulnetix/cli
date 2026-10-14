const users = require('./users.json');
const User = require('./models/user');

function show(req, res) {
  const user = users.find((u) => u.id === req.params.id);
  const admin = users.find(function (u) { return u.name === req.query.name; });
  res.json({ user, admin });
}

async function active(req, res) {
  const page = Number(req.query.page) || 0;
  const list = await User.find({ active: true }).skip(page * 20).limit(20);
  res.json(list);
}

module.exports = { show, active };
