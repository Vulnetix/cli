'use strict';

const fs = require('fs');
const express = require('express');

const app = express();

app.get('/file', (req, res) => {
  fs.readFile(req.query.path, 'utf8', (err, data) => {
    if (err) return res.status(404).end();
    res.send(data);
  });
});

module.exports = app;
