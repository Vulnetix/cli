const express = require('express');
const session = require('express-session');

const app = express();
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
~>      maxAge: 1000 * 60 * 60 * 24 * 90,
    },
  })
);

module.exports = app;
