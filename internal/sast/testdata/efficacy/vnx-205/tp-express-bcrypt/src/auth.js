const bcrypt = require('bcrypt');

async function login(req, res) {
  const user = await User.findOne({ email: req.body.email });
~>  if (!user) {
    return res.status(401).json({ error: 'Login failed' });
  }
  const ok = await bcrypt.compare(req.body.password, user.hash);
  if (!ok) return res.status(401).json({ error: 'Login failed' });
  res.json({ token: sign(user) });
}

async function login2(req, res) {
  const account = await Account.findOne({ name: req.body.name });
~>  if (!account || !(await bcrypt.compare(req.body.password, account.hash))) {
    return res.sendStatus(401);
  }
  res.sendStatus(204);
}

module.exports = { login, login2 };
