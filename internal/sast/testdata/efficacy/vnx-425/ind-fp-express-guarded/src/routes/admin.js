const express = require('express');
const { isLoggedIn, isAdmin } = require('../middleware/auth');
const ctrl = require('../controllers/admin');

const app = express.Router();

app.get('/admin/users', isLoggedIn, isAdmin, ctrl.listUsers);
app.post('/admin/users/:id/ban', isLoggedIn, isAdmin, ctrl.ban);
app.get('/products', ctrl.listProducts);
app.delete('/admin/sessions', (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  sessions.clear();
  res.sendStatus(204);
});
app.get('/admin', (req, res) => res.redirect('/login'));
// app.get('/admin/debug', ctrl.debug);
const help = "app.get('/admin/x', handler)";
module.exports = app;
