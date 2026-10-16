'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');

const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');
const app = express();

app.get('/assets/:name', (req, res) => {
  const filePath = path.resolve(PUBLIC_DIR, req.params.name);
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) {
    return res.status(403).end();
  }
  fs.createReadStream(filePath).pipe(res);
});

module.exports = app;
