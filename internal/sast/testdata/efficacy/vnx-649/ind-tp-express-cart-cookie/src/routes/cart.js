const express = require('express');
const router = express.Router();

router.get('/checkout', (req, res) => {
~>  const cart = JSON.parse(Buffer.from(req.cookies.cart, 'base64').toString('utf8'));
  const total = cart.items.reduce((sum, i) => sum + i.price * i.qty, 0);
  res.render('checkout', { cart, total, discount: cart.discount });
});

module.exports = router;
