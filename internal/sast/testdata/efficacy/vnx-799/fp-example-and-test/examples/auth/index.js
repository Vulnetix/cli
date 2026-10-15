const app = require('express')();

app.post('/login', function (req, res) {
  res.redirect('/');
});
