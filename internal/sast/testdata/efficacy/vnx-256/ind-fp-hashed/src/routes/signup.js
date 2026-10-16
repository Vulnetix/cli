const bcrypt = require("bcrypt");
const User = require("../models/account");

module.exports = async function signup(req, res) {
  const hash = await bcrypt.hash(req.body.password, 12);
  const user = await User.create({ email: req.body.email, password: hash });
  res.status(201).json({ id: user.id });
};
