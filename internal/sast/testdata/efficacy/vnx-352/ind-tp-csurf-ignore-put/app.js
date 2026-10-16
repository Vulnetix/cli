const express = require('express');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
~>app.use(csurf({ cookie: true, ignoreMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT'] }));

app.put('/profile', (req, res) => {
  req.user.update(req.body);
  res.redirect('/profile');
});

module.exports = app;
