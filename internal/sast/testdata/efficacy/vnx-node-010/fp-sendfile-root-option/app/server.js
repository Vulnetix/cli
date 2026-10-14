const express = require('express');
const path = require('path');

const app = express();
const PUBLIC_DIR = path.join(__dirname, 'public');

app.use(express.static(PUBLIC_DIR));

app.get('/files/:name', (req, res) => {
  res.sendFile(req.params.name, { root: PUBLIC_DIR });
});

app.get('/get/:name', (req, res) => {
  res.download(req.params.name, { root: PUBLIC_DIR, dotfiles: 'deny' });
});

module.exports = app;
