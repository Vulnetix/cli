const express = require('express');
const app = express();

~>app.post('/admin/reset-database', async (req, res) => {
  await db.reset();
  res.json({ ok: true });
});

app.get('/status', (req, res) => res.send('ok'));

app.listen(3000);
