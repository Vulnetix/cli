const express = require('express');
const router = express.Router();

router.get('/login/done', (req, res) => {
~>  return res.redirect(req.query.url);
});

router.post('/logout', (req, res) => {
~>  res.redirect(302, req.body.returnTo);
});

module.exports = router;
