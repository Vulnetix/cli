const express = require('express');
const zlib = require('zlib');

const router = express.Router();

router.post('/telemetry', express.raw({ type: '*/*', limit: '1mb' }), (req, res) => {
  let raw = req.body;
  if (req.get('content-encoding') === 'gzip') {
~>    raw = zlib.gunzipSync(req.body);
  }
  const batch = JSON.parse(raw.toString('utf8'));
  res.status(202).json({ received: batch.length });
});

module.exports = router;
