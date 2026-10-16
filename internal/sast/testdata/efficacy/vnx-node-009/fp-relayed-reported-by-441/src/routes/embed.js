const express = require('express');
const axios = require('axios');

const router = express.Router();

// The upstream body is sent back to the client: an open proxy, reported by
// VNX-441. This rule leaves the line to it.
router.get('/embed', async (req, res) => {
  const upstream = await axios.get(req.query.url);
  res.send(upstream.data);
});

module.exports = router;
