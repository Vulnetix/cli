const express = require('express');
const { requireAdmin, isLoggedIn } = require('./auth');
const db = require('./db');
const adminRouter = require('./routes/admin');

const app = express();

app.get('/admin/users', isLoggedIn, requireAdmin, async (req, res) => {
  res.json(await db.users.findAll());
});

app.post('/admin/flags', (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  db.flags.update(req.body);
  res.sendStatus(204);
});

app.use('/admin', isLoggedIn, requireAdmin, adminRouter);
