const express = require('express');
const router = express.Router();

router.post('/users/delete', (req, res) => {
~>  if (req.body.isAdmin) {
    return deleteUser(req.body.id, res);
  }
  res.status(403).end();
});

router.get('/panel', (req, res) => {
~>  if (req.query.role === 'admin') {
    return res.render('panel');
  }
  res.status(403).end();
});

router.get('/stats', (req, res) => {
  const level = req.headers['x-user-role'];
~>  if (level === 'admin') return res.json(stats());
  res.status(403).end();
});
