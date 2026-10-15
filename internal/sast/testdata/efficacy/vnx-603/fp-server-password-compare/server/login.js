const bcrypt = require('bcrypt');

async function login(req, res) {
  const password = req.body.password;
  if (password === '') {
    return res.status(400).send('missing');
  }
  const ok = await bcrypt.compare(password, user.hash);
  res.send(ok);
}

module.exports = { login };
