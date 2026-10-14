const express = require('express');
const session = require('express-session');

const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
~>    secure: false, // TODO: enable once TLS is in front
    maxAge: 3600000,
  },
}));

app.listen(3000);
