const router = require('express').Router();

router.get('/prices.js', (req, res) => {
  const callback = String(req.query.callback || 'onPrices').replace(/[^\w$.]/g, '');
  const prices = { btc: 1, eth: 2 };
  res.type('application/javascript');
  res.send(callback + '(' + JSON.stringify(prices) + ');');
});

module.exports = router;
