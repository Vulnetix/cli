const express = require('express');
const sess = require('express-session');
const RedisStore = require('connect-redis').default;

const app = express();
app.use(sess({
  store: new RedisStore({ client: redis }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60,
~>    secure: false,
    sameSite: 'lax',
  },
}));
