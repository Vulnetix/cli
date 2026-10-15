const jwt = require('jsonwebtoken');

async function login(req, res) {
  const user = await findUser(req.body.email);
~>  const token = jwt.sign(
    { sub: user.id, role: user.role },
    process.env.JWT_SECRET,
    { issuer: 'shop-api', algorithm: 'HS256' }
  );
  res.json({ token });
}

module.exports = { login };
