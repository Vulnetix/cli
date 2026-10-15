const express = require('express');
const axios = require('axios');

const router = express.Router();

router.post('/hooks/test', async (req, res) => {
  const target = req.body.callbackUrl;
~>  const r = await axios.post(target, {
    event: 'ping',
    sentAt: Date.now(),
  });
  res.json({ status: r.status });
});

module.exports = router;
