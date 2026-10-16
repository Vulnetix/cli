const jwt = require('jsonwebtoken');

async function login(req, res) {
  const user = await findUser(req.body.email, req.body.password);
  if (!user) return res.status(401).end();
~>  const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_KEY);
  res.json({ token });
}
module.exports = { login };
