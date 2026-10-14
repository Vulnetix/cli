const express = require('express');
const cookieSession = require('cookie-session');

const app = express();

// cookie-session marks the cookie Secure automatically on HTTPS requests.
app.use(cookieSession({
  name: 'session',
  keys: [process.env.SESSION_KEY],
  maxAge: 24 * 60 * 60 * 1000,
}));
