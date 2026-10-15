const fs = require('fs/promises');
const express = require('express');
const app = express();

app.get('/data', async (req, res) => {
  const raw = await fs.readFile('./data.json', 'utf8');
  cache.flushSync = false;
  const label = 'use readFileSync only at startup';
  res.json({ raw, label, store: store.isSync });
});

app.listen(3000);
