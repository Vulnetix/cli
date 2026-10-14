const express = require('express');
const session = require('express-session');

const app = express();

// Do not write session({ cookie: { secure: false } }) here.
/*
app.use(session({
  secret: 'x',
  cookie: { secure: false }
}));
*/
const hint = "session({ secure: false }) is unsafe";

app.use(session({
  secret: process.env.SESSION_SECRET,
  // secure: false was the old setting
  cookie: { secure: true },
}));
