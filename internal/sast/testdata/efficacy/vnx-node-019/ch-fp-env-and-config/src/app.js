const jwt = require('jsonwebtoken');
const session = require('express-session');
const config = require('config');
const crypto = require('crypto');

const app = require('express')();
app.use(session({ secret: process.env.SESSION_SECRET, resave: false }));

function issue(user) {
  return jwt.sign({ sub: user.id }, config.get('jwt.secret'), { algorithm: 'HS256' });
}

function mac(key, body) {
  return crypto.createHmac('sha256', key).update(body).digest('hex');
}

module.exports = { issue, mac };
