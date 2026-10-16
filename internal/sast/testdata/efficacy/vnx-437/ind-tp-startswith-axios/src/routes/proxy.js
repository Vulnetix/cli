const express = require('express');
const axios = require('axios');

const router = express.Router();

router.get('/image', async (req, res, next) => {
  const target = String(req.query.src || '');
  if (!target.startsWith('https://images.acme-cdn.com')) {
    return res.status(400).json({ error: 'unsupported image host' });
  }
  try {
~>    const upstream = await axios.get(target, { responseType: 'stream', timeout: 5000 });
    upstream.data.pipe(res);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
