const express = require('express');

const router = express.Router();

router.get('/admin/users', (req, res) => {
~>  if (req.headers['x-role'] === 'admin') {
    return res.json(users.all());
  }
  res.status(403).end();
});

router.get('/reports', (req, res) => {
  const isAdmin = req.cookies.isAdmin === 'true';
~>  if (isAdmin) {
    return res.json(reports.all());
  }
  res.json(reports.mine(req.user.id));
});

router.get('/orders', (req, res) => {
~>  const rows = req.query.admin ? orders.all() : orders.forUser(req.user.id);
  res.json(rows);
});

module.exports = router;
