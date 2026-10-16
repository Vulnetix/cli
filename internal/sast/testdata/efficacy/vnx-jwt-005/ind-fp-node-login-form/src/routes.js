const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

async function login(req, res) {
  const { email, password } = req.body;
  const user = await users.findByEmail(email);
  if (!user || !(await bcrypt.compare(password, user.hash))) return res.sendStatus(401);
  const token = jwt.sign({ id: user.id }, process.env.JWT_KEY, { expiresIn: '1h' });
  res.json({ token });
}
module.exports = { login };
