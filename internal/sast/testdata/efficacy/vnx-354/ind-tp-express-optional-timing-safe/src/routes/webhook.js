const crypto = require('crypto');
const express = require('express');

const router = express.Router();

router.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.get('x-signature');
  const expected = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET)
    .update(req.body)
    .digest('hex');
~>  if (signature && !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return res.status(401).end();
  }
  queue.push(JSON.parse(req.body));
  res.sendStatus(202);
});

module.exports = router;
