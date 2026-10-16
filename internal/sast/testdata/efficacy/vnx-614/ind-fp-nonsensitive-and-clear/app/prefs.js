const express = require('express');
const app = express();

app.post('/theme', (req, res) => {
  res.cookie('theme', req.body.theme);
  res.cookie('lang', 'en');
  res.send('ok');
});

app.post('/logout', (req, res) => {
  res.cookie('token', '', { maxAge: 0 });
  res.clearCookie('session');
  res.redirect('/');
});
