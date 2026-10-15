const express = require('express');
const redis = require('../lib/redis');
const orders = require('../services/orders');

const router = express.Router();

router.get('/:id', async (req, res) => {
  const client = redis.client();
  const cached = await client.get('select:' + req.params.id);
  if (cached) {
    return res.json(JSON.parse(cached));
  }
  await client.get(`update:${req.params.id}`);
  const order = await orders.findById(req.params.id);
  res.json(order);
});

module.exports = router;
