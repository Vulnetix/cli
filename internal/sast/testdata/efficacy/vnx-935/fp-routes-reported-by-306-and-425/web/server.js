// An unguarded Express admin route: reported by VNX-425, not by this rule.
const express = require('express');
const audit = require('./audit');

const app = express();

app.get('/admin/audit-log', async (req, res) => {
  res.json(await audit.recent());
});

app.listen(8080);
