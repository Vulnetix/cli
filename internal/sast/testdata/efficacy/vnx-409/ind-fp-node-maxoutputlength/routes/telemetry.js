const express = require('express');
const zlib = require('zlib');

const router = express.Router();
const MAX_INFLATED = 4 * 1024 * 1024;

router.post('/telemetry', express.raw({ type: '*/*', limit: '1mb' }), (req, res) => {
  let raw = req.body;
  if (req.get('content-encoding') === 'gzip') {
    raw = zlib.gunzipSync(req.body, { maxOutputLength: MAX_INFLATED });
  }
  res.status(202).json({ bytes: raw.length });
});

module.exports = router;
