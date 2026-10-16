const fs = require('fs');
const express = require('express');
const cert = fs.readFileSync('./certs/server.pem');
const config = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
const app = express();
app.get('/health', (req, res) => {
  res.json({ ok: true, name: config.name });
});
