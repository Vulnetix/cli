const crypto = require('crypto');
const express = require('express');

const router = express.Router();

router.post('/hooks/partner', express.raw({ type: '*/*' }), (req, res) => {
  const sig = req.get('X-Partner-Signature');
  const digest = crypto
    .createHmac('sha256', process.env.PARTNER_KEY)
    .update(req.body)
    .digest('hex');
~>  if (sig !== digest) {
    return res.sendStatus(401);
  }
  res.sendStatus(200);
});

module.exports = router;
