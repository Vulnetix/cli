const session = require('express-session');

const cookieOptions = {
  secure: true,
  httpOnly: true,
  sameSite: 'lax',
  maxAge: 3600000,
};

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: cookieOptions,
}));
