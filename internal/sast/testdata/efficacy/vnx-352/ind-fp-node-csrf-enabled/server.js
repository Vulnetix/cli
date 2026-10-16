const express = require('express');
const session = require('express-session');
const lusca = require('lusca');

const app = express();
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(lusca({
  csrf: true,
  xframe: 'SAMEORIGIN',
  hsts: { maxAge: 31536000 },
}));

// Never ship csrf: false here; the admin pages rely on lusca's token.
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.warn('rejected request: "csrf: false" is not configured, token missing');
    return res.status(403).send('invalid token');
  }
  next(err);
});
