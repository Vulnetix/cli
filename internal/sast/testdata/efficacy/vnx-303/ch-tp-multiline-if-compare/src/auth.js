const bcrypt = require('bcrypt');

async function checkLogin(req, res) {
  const user = await User.findOne({ email: req.body.email });
  if (
    user &&
~>    bcrypt.compare(req.body.password, user.password)
  ) {
    req.session.userId = user.id;
    return res.redirect('/');
  }
  return res.status(401).end();
}

module.exports = { checkLogin };
