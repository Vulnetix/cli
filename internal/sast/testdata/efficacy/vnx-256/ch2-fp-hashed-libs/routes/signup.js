const bcrypt = require("bcrypt");

async function signup(req, res) {
  const hash = await bcrypt.hash(req.body.password, 12);
  await User.create({ email: req.body.email, password: hash });
  res.sendStatus(201);
}
