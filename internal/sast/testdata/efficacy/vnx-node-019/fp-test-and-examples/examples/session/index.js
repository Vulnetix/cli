const express = require('express');
const session = require('express-session');

const app = express();

app.use(session({
  resave: false,
  saveUninitialized: false,
  secret: 'keyboard cat',
}));

app.listen(3000);
