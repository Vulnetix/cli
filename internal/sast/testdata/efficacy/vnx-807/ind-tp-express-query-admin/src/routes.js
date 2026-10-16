const express = require('express');
const app = express();

app.get('/dashboard', (req, res) => {
~>  if (req.query.admin === 'true') {
    return res.render('admin');
  }
  res.render('user');
});
