const express = require('express');
const db = require('./db');

const app = express();
app.use(express.json());

app.post('/admin/flags', (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  db.flags.update(req.body);
  res.sendStatus(204);
});

app.get('/manager/report', (req, res) => res.json(db.report()));

module.exports = app;
