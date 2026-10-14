const jwt = require('jsonwebtoken');

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await Users.check(email, password);
  const claims = { sub: user.id, passwordChangedAt: user.passwordChangedAt, hasPassword: true };
  // never put { password } in the payload
  const token = jwt.sign(claims, process.env.JWT_KEY, { expiresIn: '1h' });
  res.json({ token, message: "password: accepted" });
});

const form = { password: '', email: '' };
module.exports = { form };
