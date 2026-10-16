const express = require('express');
const session = require('express-session');
const { signJwt } = require('./jwt');

const app = express();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
~>      secure: false,
      maxAge: 1000 * 60 * 60,
    },
  })
);

app.post('/api/login', async (req, res) => {
  const user = await app.locals.users.verify(req.body.email, req.body.password);
  const token = signJwt({ sub: user.id });
~>  res.cookie('refreshToken', token, { httpOnly: true, sameSite: 'strict' });
~>  res.cookie('access_token', token);
  res.cookie('lang', 'en');
  res.json({ ok: true });
});

module.exports = app;
