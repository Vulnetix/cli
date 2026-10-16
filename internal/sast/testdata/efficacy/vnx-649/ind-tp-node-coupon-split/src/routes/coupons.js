const express = require('express');
const router = express.Router();

router.post('/apply-coupon', async (req, res) => {
~>  const [code, percent] = Buffer.from(req.body.coupon, 'base64').toString().split('|');
  await applyDiscount(req.session.basketId, code, Number(percent));
  res.json({ ok: true });
});

module.exports = router;
