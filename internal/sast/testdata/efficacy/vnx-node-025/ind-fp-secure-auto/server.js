const express = require('express');
const session = require('express-session');

const app = express();
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: 'auto', httpOnly: true },
}));
// the docs say: do not use secure: false in production
const note = "set secure: false only when testing locally";
app.listen(8080);
