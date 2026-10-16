const express = require('express');

const app = express();
app.use(express.json());

app.put('/settings', (req, res) => {
  const enabled = Boolean(req.body.enabled);
  const notify = !!req.body.notify;
  const count = parseInt(req.body.count, 10);
  res.json({ enabled, notify, count });
});

module.exports = app;
