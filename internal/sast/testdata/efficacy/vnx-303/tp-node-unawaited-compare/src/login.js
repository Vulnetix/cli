const bcrypt = require('bcrypt');

async function login(req, res) {
  const user = await User.findOne({ email: req.body.email });
~>  if (user && bcrypt.compare(req.body.password, user.passwordHash)) {
    req.session.userId = user.id;
    return res.redirect('/');
  }
  res.status(401).end();
}

function checkPassword(user, password) {
~>  const ok = bcrypt.compare(password, user.hash);
  if (!ok) {
    throw new Error('bad password');
  }
}
