const express = require('express');
const { Worker } = require('worker_threads');
const app = express();
const TASKS = new Set(['resize', 'thumb']);

app.get('/task', (req, res) => {
  const kind = req.query.kind;
  if (!TASKS.has(kind)) {
    return res.sendStatus(400);
  }
  const w = new Worker(`./tasks/${kind}.js`);
  const n = parseInt(req.query.shard, 10);
  const w2 = new Worker(`./tasks/shard-${n}.js`);
  res.json({ ok: !!(w && w2) });
});
