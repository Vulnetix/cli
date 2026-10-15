const express = require('express');
const passport = require('passport');

const app = express();
app.use('/admin', passport.authenticate('jwt', { session: false }));

app.post('/admin/cache/flush', (req, res) => {
  cache.flushAll();
  res.sendStatus(204);
});

module.exports = app;
