const express = require('express');
const app = express();

app.use((req, res, next) => {
~>  if (/^\/billing/.test(req.path) && !req.session.userId) {
    return res.redirect('/login');
  }
  next();
});

module.exports = app;
