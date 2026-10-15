const express = require('express');
const { requireAdmin } = require('./guards');
const app = express();

app.post('/admin/reset-database', requireAdmin, async (req, res) => {
  res.json({ ok: true });
});
app.get('/admin/users', isLoggedIn, isAdmin, listUsers);
