const express = require('express');
const { Worker } = require('worker_threads');
const { NodeVM } = require('vm2');
const app = express();

app.get('/task', (req, res) => {
  const { file } = req.query;
~>  const w = new Worker(`./tasks/${file}`);
  w.on('message', (m) => res.json(m));
});

app.post('/sandbox', (req, res) => {
  const vm = new NodeVM({ sandbox: {} });
~>  res.json(vm.runFile(req.body.path));
});
