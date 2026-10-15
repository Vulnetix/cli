const express = require('express');
const app = express();
app.use(express.json());

app.post('/cart', (req, res) => {
  if (!Array.isArray(req.body.items)) {
    return res.status(400).json({ error: 'items must be an array' });
  }
  const total = req.body.items.length;
  res.json({ total });
});
