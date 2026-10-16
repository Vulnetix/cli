'use strict';

const fs = require('fs');
const express = require('express');

const PUBLIC_DIR = '/srv/www/public/';
const app = express();

app.get('/assets/:name', (req, res) => {
  const filePath = PUBLIC_DIR + req.params.name;
~>  if (!filePath.startsWith(PUBLIC_DIR)) {
    return res.status(403).end();
  }
  fs.createReadStream(filePath).pipe(res);
});

module.exports = app;
