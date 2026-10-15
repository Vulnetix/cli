const express = require('express');
const router = express.Router();

router.get('/admin', (req, res) => {
~>  if (req.cookies.role === 'admin') {
    return res.render('admin');
  }
~>  if (req.cookies['isAdmin'] == 'true' || req.cookies?.is_staff) {
    return res.render('staff');
  }
  res.sendStatus(403);
});

module.exports = router;
