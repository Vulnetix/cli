const crypto = require('crypto');
const express = require('express');
const router = express.Router();

router.get('/checkout', (req, res) => {
  const [payload, mac] = String(req.cookies.cart || '').split('.');
  const expected = crypto.createHmac('sha256', process.env.CART_KEY).update(payload).digest();
  const given = Buffer.from(mac || '', 'base64');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
    return res.status(400).end();
  }
  const cart = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  res.render('checkout', { cart });
});

module.exports = router;
