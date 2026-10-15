const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
~>    httpOnly: false,
~>    secure: false,
    maxAge: 3600000,
  },
}));

app.post('/login', (req, res) => {
~>  res.cookie('session', token, { httpOnly: false, maxAge: 900000 });
  res.redirect('/');
});
