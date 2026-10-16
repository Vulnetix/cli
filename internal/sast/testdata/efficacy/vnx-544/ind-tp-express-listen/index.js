const express = require('express');
const db = require('./db');

~>const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.set('X-Request-Id', req.get('X-Request-Id') || Date.now().toString(36));
  next();
});

app.get('/orders/:id', async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'not found' });
  }
  res.json(order);
});

app.listen(process.env.PORT || 8080, () => console.log('listening'));
