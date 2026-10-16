const express = require('express');
const router = express.Router();

router.get('/dashboard', (req, res) => {
~>  const view = req.query.admin === 'true' ? 'dashboard/admin' : 'dashboard/user';
  res.render(view, { title: 'Dashboard' });
});

module.exports = router;
