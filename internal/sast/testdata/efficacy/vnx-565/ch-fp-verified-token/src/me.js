const jwt = require('jsonwebtoken');

function me(req, res) {
  const token = req.cookies.user;
  const claims = jwt.verify(token, process.env.JWT_SECRET);
  if (claims.role === 'admin') return res.json({ admin: true });
  res.json({ admin: false });
}
