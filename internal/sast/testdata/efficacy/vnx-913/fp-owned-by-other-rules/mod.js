const express = require('express');
const fs = require('fs');
const vm = require('vm');
const app = express();

app.get('/m', (req, res) => {
  const m = require(req.query.module);
  process.dlopen(module, req.query.so);
  const src = fs.readFileSync(req.query.file, 'utf8');
  vm.runInNewContext(src);
  res.json(m);
});
