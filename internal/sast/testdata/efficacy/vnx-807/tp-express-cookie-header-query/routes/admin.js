const router = require('express').Router();

router.get('/admin', (req, res, next) => {
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  if (req.cookies.isAdmin === 'true') {
    return res.render('admin');
  }
~>  if (req.headers['x-user-role'] == 'admin') {
    return res.render('admin');
  }
~>  const isAdmin = req.query.admin === '1';
~>  if (req.get('X-Authenticated')) {
    return next();
  }
  res.status(403).end();
});
module.exports = router;
