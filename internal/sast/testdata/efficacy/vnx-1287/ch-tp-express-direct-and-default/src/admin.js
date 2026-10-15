const express = require('express');
const router = express.Router();

router.get('/admin', (req, res) => {
~>  if (req.query.role.includes('admin')) {
    return res.send('welcome');
  }
  const name = req.query.name || '';
~>  const clean = name.trim();
~>  const email = req.body.email.toLowerCase();
  res.json({ clean, email });
});

module.exports = router;
