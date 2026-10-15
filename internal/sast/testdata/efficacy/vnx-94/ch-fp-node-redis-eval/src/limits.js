const express = require('express');
const app = express();

const INCR_SCRIPT = "local n = redis.call('INCR', KEYS[1]) return n";

app.post('/hit/:id', async (req, res) => {
  const n = await redis.eval(INCR_SCRIPT, 1, req.params.id);
  const cfg = JSON.parse(req.body.config);
  setTimeout(() => notify(req.body.user), 1000);
  const total = await page.$eval('#total', (el) => el.textContent);
  res.json({ n, cfg, total });
});
