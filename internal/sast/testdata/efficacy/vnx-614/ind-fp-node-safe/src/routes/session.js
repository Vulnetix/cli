const nodemailer = require('nodemailer');
const config = require('../config');

const cookieOptions = {
  httpOnly: true,
  secure: config.isProduction,
  sameSite: 'strict',
};

const mailer = nodemailer.createTransport({
  host: 'smtp.internal',
  port: 587,
  secure: false,
});

function login(req, res, token) {
  res.cookie('token', token, cookieOptions);
  res.cookie('session', token, { ...cookieOptions, maxAge: 3600 * 1000 });
  res.cookie('refresh_token', token, { httpOnly: true, secure: true, sameSite: 'lax' });
  res.cookie('theme', req.query.theme || 'light');
  res.json({ ok: true });
}

function logout(req, res) {
  res.clearCookie('token');
  res.cookie('session', '', { maxAge: 0 });
  res.cookie('auth_token', null);
  res.sendStatus(204);
}

function rememberClientSide(token) {
  document.cookie = 'access_token=' + token + '; path=/; Secure; SameSite=Strict';
}

module.exports = { login, logout, rememberClientSide, mailer };
