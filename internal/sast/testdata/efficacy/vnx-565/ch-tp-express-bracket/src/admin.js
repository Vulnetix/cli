const express = require('express');
const router = express.Router();

router.get('/admin', (req, res) => {
~>  if (req.cookies['user_role'] === 'admin') {
    return res.render('admin');
  }
  res.sendStatus(403);
});

router.get('/panel', (req, res) => {
~>  if (req.cookies.isAdmin == 'true') return res.render('panel');
  res.sendStatus(403);
});

module.exports = router;
