const express = require('express');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('./config');

const app = express();
const secret = process.env.JWT_SECRET;

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
}));

function issue(user) {
  return jwt.sign({ sub: user.id }, secret, { algorithm: 'HS256' });
}

function verify(token) {
  return jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
}

function digest(body) {
  return crypto.createHmac('sha256', config.webhookKey).update(body).digest('hex');
}

const jwtSecret = process.env.JWT_SECRET;
const sessionSecret = '';
const cookieSecret = process.env.COOKIE_SECRET || 'dev-only';
app.use(require('cookie-parser')(cookieSecret));

module.exports = { app, issue, verify, digest, jwtSecret, sessionSecret };
