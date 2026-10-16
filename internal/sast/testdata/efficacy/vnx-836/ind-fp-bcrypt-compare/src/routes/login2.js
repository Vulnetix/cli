const bcrypt = require('bcrypt');

async function login(req, res) {
  const user = await Users.findOne({ email: req.body.email });
  const ok = await bcrypt.compare(req.body.password, user.passwordHash);
  if (!ok) return res.status(401).end();
  res.json({ token: sign(user) });
}
