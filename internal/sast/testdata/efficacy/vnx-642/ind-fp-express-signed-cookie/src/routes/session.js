const express = require('express');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser(process.env.COOKIE_SECRET));

app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  if (!user) return res.sendStatus(401);
  res.cookie('role', user.role, { signed: true, httpOnly: true, sameSite: 'strict' });
  res.json({ ok: true });
});

app.get('/me', (req, res) => {
  const role = req.signedCookies.role;
  res.json({ role });
});

module.exports = app;
