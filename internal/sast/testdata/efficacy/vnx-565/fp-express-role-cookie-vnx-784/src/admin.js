const express = require('express');
const router = express.Router();

router.get('/admin', (req, res) => {
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  if (req.cookies.role === 'admin') {
    return res.render('admin');
  }
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  if (req.cookies['isAdmin'] == 'true' || req.cookies?.is_staff) {
    return res.render('staff');
  }
  res.sendStatus(403);
});

module.exports = router;
