const router = require('express').Router();
const { lookup } = require('../geo');

router.get('/geo', async (req, res) => {
  const result = await lookup(req.ip);
  // Express validates the callback name for us.
  res.jsonp(result);
});

module.exports = router;
