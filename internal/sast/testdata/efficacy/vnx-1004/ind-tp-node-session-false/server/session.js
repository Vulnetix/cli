const express = require('express');
const session = require('express-session');

const app = express();
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
~>    httpOnly: false,
    maxAge: 3600000,
  },
}));
