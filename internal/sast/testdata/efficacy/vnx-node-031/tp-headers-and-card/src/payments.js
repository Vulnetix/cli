const log = require('./log');

module.exports = function charge(req, res) {
~>  log.info('auth header', req.headers.authorization);
  const { cardNumber, cvv } = req.body;
~>  console.error('charge failed', cardNumber, cvv);
  res.sendStatus(402);
};
