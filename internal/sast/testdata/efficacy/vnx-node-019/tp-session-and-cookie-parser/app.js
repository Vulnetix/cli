const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();

~>app.use(cookieParser('cookie-signing-secret'));
app.use(session({
  name: 'sid',
~>  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
}));

function sign(body) {
~>  return crypto.createHmac('sha256', 'webhook-hmac-key').update(body).digest('hex');
}

module.exports = { app, sign };
