const express = require('express');
const session = require('express-session');
const app = express();
app.use(session({
  name: 'sid',
~>  secret: 'keyboard cat 1234',
  resave: false,
  saveUninitialized: false,
}));
