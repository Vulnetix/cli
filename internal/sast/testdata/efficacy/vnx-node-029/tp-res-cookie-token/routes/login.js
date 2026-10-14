const jwt = require('jsonwebtoken');

module.exports = function login(req, res) {
  const token = jwt.sign({ sub: req.user.id }, process.env.JWT_SECRET);
~>  res.cookie('token', token);
~>  res.cookie("session", req.sessionID, { maxAge: 900000 });
  res.redirect('/');
};
