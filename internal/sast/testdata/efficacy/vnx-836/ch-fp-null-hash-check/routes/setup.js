const User = require('../models/user');

async function firstLogin(req, res) {
  const user = await User.findById(req.params.id);
  if (user.passwordHash === null && req.body.password) {
    return res.redirect('/set-password');
  }
  return res.redirect('/login');
}

module.exports = { firstLogin };
