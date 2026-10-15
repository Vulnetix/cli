const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
~>    maxAge: 365 * 24 * 60 * 60 * 1000,
  },
}));
