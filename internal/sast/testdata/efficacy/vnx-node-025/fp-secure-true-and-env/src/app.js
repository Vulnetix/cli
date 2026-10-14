const express = require('express');
const session = require('express-session');

const app = express();
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: 'strict' },
}));

const admin = express();
admin.use(session({
  secret: process.env.ADMIN_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
  },
}));

const api = express();
api.use(session({ secret: process.env.API_SECRET, cookie: { secure: 'auto' } }));
